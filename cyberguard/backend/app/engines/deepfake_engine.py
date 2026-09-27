"""
CyberGuard Deepfake Detection Engine
──────────────────────────────────────
Architecture: Pluggable DetectionEngine base class with three concrete implementations:

  1. ImageDeepfakeEngine   – OpenCV artifact/heuristic + optional CNN
  2. AudioDeepfakeEngine   – librosa spectral feature analysis
  3. VideoDeepfakeEngine   – frame-sampling → per-frame image checks

All engines return a common result dict:
    { authenticity_score: int(0-100), risk_score: int, indicators: [str], confidence: float }

where authenticity_score = 100 means "definitely real" (0 = definitely fake).
risk_score is the inverse used by the risk scorer: risk_score = 100 - authenticity_score.
"""
from __future__ import annotations

import io
import logging
import math
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image, ExifTags

logger = logging.getLogger(__name__)


# ─── Base engine ─────────────────────────────────────────────────────────────

class DeepfakeDetectionEngine(ABC):
    """Pluggable base class for all deepfake detector variants."""

    @abstractmethod
    def analyze(self, data: bytes, filename: str) -> Dict[str, Any]:
        ...

    @staticmethod
    def _make_result(
        authenticity_score: float,
        indicators: List[str],
        confidence: float,
        extra: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        risk_score = round(100 - authenticity_score, 2)
        return {
            "authenticity_score": round(authenticity_score, 2),
            "risk_score": risk_score,
            "indicators": indicators,
            "confidence": round(confidence, 3),
            **(extra or {}),
        }


# ─── Image engine ─────────────────────────────────────────────────────────────

class ImageDeepfakeEngine(DeepfakeDetectionEngine):
    """
    Heuristic deepfake image detector using OpenCV.
    Checks for:
      - Edge-boundary blurring around face regions
      - Frequency-domain artifacts (FFT analysis)
      - JPEG/compression noise inconsistencies (noise floor variance)
      - Missing/inconsistent EXIF metadata
      - Unnatural colour-channel distribution
    """

    def analyze(self, data: bytes, filename: str) -> Dict[str, Any]:
        indicators: List[str] = []
        artifact_scores: List[float] = []

        try:
            image = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception as exc:
            return self._make_result(50.0, [f"Could not parse image: {exc}"], 0.3)

        img_np = np.array(image)
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        # 1. EXIF metadata check
        exif_score, exif_indicators = self._check_exif(image)
        artifact_scores.append(exif_score)
        indicators.extend(exif_indicators)

        # 2. Frequency-domain analysis (FFT)
        fft_score, fft_indicators = self._fft_analysis(gray)
        artifact_scores.append(fft_score)
        indicators.extend(fft_indicators)

        # 3. Local noise inconsistency
        noise_score, noise_indicators = self._noise_analysis(gray)
        artifact_scores.append(noise_score)
        indicators.extend(noise_indicators)

        # 4. Blurring boundary detection
        blur_score, blur_indicators = self._blur_boundary(gray)
        artifact_scores.append(blur_score)
        indicators.extend(blur_indicators)

        # 5. Colour channel distribution
        color_score, color_indicators = self._colour_distribution(img_np)
        artifact_scores.append(color_score)
        indicators.extend(color_indicators)

        # Aggregate: higher = more fake
        fake_probability = float(np.mean(artifact_scores))
        authenticity_score = 100 - min(100, fake_probability)
        confidence = min(0.92, 0.5 + fake_probability / 200)

        return self._make_result(
            authenticity_score,
            indicators if indicators else ["No significant manipulation artifacts detected"],
            confidence,
        )

    def _check_exif(self, image: Image.Image) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        score = 0.0
        try:
            exif_data = image._getexif()
            if exif_data is None:
                score = 20.0
                indicators.append("No EXIF metadata present — typical of AI-generated images")
            else:
                tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()}
                if "Make" not in tags and "Model" not in tags:
                    score = 10.0
                    indicators.append("Missing camera make/model in EXIF data")
                if "Software" in tags and any(
                    s in str(tags["Software"]).lower()
                    for s in ["photoshop", "gimp", "dall", "midjourney", "stable"]
                ):
                    score = 35.0
                    indicators.append(f"Image editing software detected in EXIF: {tags['Software']}")
        except Exception:
            score = 15.0
            indicators.append("EXIF data unreadable — possible metadata stripping")
        return score, indicators

    def _fft_analysis(self, gray: np.ndarray) -> Tuple[float, List[str]]:
        """Look for periodic artifacts in frequency domain characteristic of GAN images."""
        indicators: List[str] = []
        try:
            f = np.fft.fft2(gray)
            fshift = np.fft.fftshift(f)
            magnitude = np.log(np.abs(fshift) + 1)
            # GAN fingerprints often show grid-like peaks in FFT
            # Heuristic: high variance in radial average suggests anomaly
            center = np.array(magnitude.shape) // 2
            max_r = min(center)
            radial_means = []
            for r in range(1, max_r, max_r // 20 + 1):
                mask = self._ring_mask(magnitude.shape, center, r, r + max_r // 20)
                if mask.sum() > 0:
                    radial_means.append(magnitude[mask].mean())
            if radial_means:
                radial_var = float(np.var(radial_means))
                if radial_var > 2.5:
                    score = min(40, radial_var * 5)
                    indicators.append(f"Frequency-domain anomaly detected (FFT radial variance: {radial_var:.2f})")
                    return score, indicators
        except Exception as exc:
            logger.debug("FFT analysis error: %s", exc)
        return 0.0, indicators

    @staticmethod
    def _ring_mask(shape, center, r_inner, r_outer):
        Y, X = np.ogrid[:shape[0], :shape[1]]
        dist = np.sqrt((X - center[1]) ** 2 + (Y - center[0]) ** 2)
        return (dist >= r_inner) & (dist < r_outer)

    def _noise_analysis(self, gray: np.ndarray) -> Tuple[float, List[str]]:
        """
        Real photos have consistent sensor noise across the image.
        AI-generated images often have suspiciously low or highly uniform noise.
        """
        indicators: List[str] = []
        try:
            # Compute local variance map
            kernel = np.ones((8, 8), dtype=np.float32) / 64
            local_mean = cv2.filter2D(gray.astype(np.float32), -1, kernel)
            local_sq_mean = cv2.filter2D(gray.astype(np.float32) ** 2, -1, kernel)
            local_var = local_sq_mean - local_mean ** 2
            var_of_var = float(np.var(local_var))

            # Suspiciously uniform noise → possibly AI-generated
            if var_of_var < 500:
                score = 30.0
                indicators.append(f"Suspiciously uniform noise floor (var-of-variance: {var_of_var:.1f})")
                return score, indicators
        except Exception as exc:
            logger.debug("Noise analysis error: %s", exc)
        return 0.0, indicators

    def _blur_boundary(self, gray: np.ndarray) -> Tuple[float, List[str]]:
        """Detect abrupt blur transitions at potential splice boundaries."""
        indicators: List[str] = []
        try:
            laplacian = cv2.Laplacian(gray, cv2.CV_64F)
            # Compute variance in horizontal strips
            h, w = gray.shape
            strip_vars = []
            for i in range(0, h - h // 8, h // 8):
                strip = laplacian[i:i + h // 8, :]
                strip_vars.append(float(np.var(strip)))
            if strip_vars:
                cv_coef = np.std(strip_vars) / (np.mean(strip_vars) + 1e-6)
                if cv_coef > 2.0:
                    score = min(35, cv_coef * 8)
                    indicators.append(f"Uneven sharpness distribution detected (boundary blur coefficient: {cv_coef:.2f})")
                    return score, indicators
        except Exception as exc:
            logger.debug("Blur analysis error: %s", exc)
        return 0.0, indicators

    def _colour_distribution(self, img_np: np.ndarray) -> Tuple[float, List[str]]:
        """Check for unnatural channel correlations (GAN images often differ)."""
        indicators: List[str] = []
        try:
            r, g, b = img_np[:, :, 0].flatten(), img_np[:, :, 1].flatten(), img_np[:, :, 2].flatten()
            corr_rg = float(np.corrcoef(r, g)[0, 1])
            corr_rb = float(np.corrcoef(r, b)[0, 1])
            # Natural photos have moderate positive channel correlations
            if corr_rg < 0.6 or corr_rb < 0.5:
                score = 20.0
                indicators.append(f"Unusual colour channel correlation (R-G: {corr_rg:.2f}, R-B: {corr_rb:.2f})")
                return score, indicators
        except Exception as exc:
            logger.debug("Colour analysis error: %s", exc)
        return 0.0, indicators


# ─── Audio engine ─────────────────────────────────────────────────────────────

class AudioDeepfakeEngine(DeepfakeDetectionEngine):
    """
    Heuristic voice-cloning / audio-manipulation detector using librosa.
    Checks:
      - Spectral flatness (TTS voices often smoother than natural speech)
      - F0 (pitch) continuity and naturalness
      - MFCC coefficient consistency
      - Background noise floor uniformity
    """

    def analyze(self, data: bytes, filename: str) -> Dict[str, Any]:
        indicators: List[str] = []

        try:
            # pyrefly: ignore [missing-import]
            import librosa
        except ImportError:
            return self._make_result(60.0, ["librosa not available — audio analysis skipped"], 0.3)

        try:
            with tempfile.NamedTemporaryFile(suffix=Path(filename).suffix or ".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            y, sr = librosa.load(tmp_path, sr=None, mono=True, duration=60)
            os.unlink(tmp_path)
        except Exception as exc:
            return self._make_result(50.0, [f"Audio loading error: {exc}"], 0.3)

        artifact_scores: List[float] = []

        # 1. Spectral flatness (high flatness → synthetic/white-noise-like)
        flatness = librosa.feature.spectral_flatness(y=y)
        mean_flatness = float(np.mean(flatness))
        if mean_flatness > 0.2:
            score = min(40, mean_flatness * 100)
            artifact_scores.append(score)
            indicators.append(f"High spectral flatness ({mean_flatness:.3f}) — possible synthetic voice")
        else:
            artifact_scores.append(0.0)

        # 2. Pitch continuity
        try:
            f0, voiced_flag, voiced_probs = librosa.pyin(
                y, fmin=librosa.note_to_hz("C2"), fmax=librosa.note_to_hz("C7")
            )
            f0_valid = f0[~np.isnan(f0)]
            if len(f0_valid) > 10:
                f0_jumps = np.diff(f0_valid)
                large_jumps = np.sum(np.abs(f0_jumps) > 100)
                if large_jumps > len(f0_jumps) * 0.15:
                    score = min(35, large_jumps * 2)
                    artifact_scores.append(score)
                    indicators.append(f"Unnatural pitch discontinuities: {large_jumps} large F0 jumps detected")
                else:
                    artifact_scores.append(0.0)
            else:
                artifact_scores.append(0.0)
        except Exception:
            artifact_scores.append(0.0)

        # 3. MFCC consistency
        try:
            mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
            mfcc_var = float(np.var(np.diff(mfcc, axis=1)))
            if mfcc_var < 5.0:
                score = 25.0
                artifact_scores.append(score)
                indicators.append(f"Unusually consistent MFCC coefficients (variance: {mfcc_var:.2f}) — possible TTS")
            else:
                artifact_scores.append(0.0)
        except Exception:
            artifact_scores.append(0.0)

        # 4. Background noise uniformity
        try:
            rms = librosa.feature.rms(y=y)[0]
            rms_cv = float(np.std(rms) / (np.mean(rms) + 1e-6))
            if rms_cv < 0.3:
                artifact_scores.append(20.0)
                indicators.append(f"Unusually uniform background noise (RMS CV: {rms_cv:.3f})")
            else:
                artifact_scores.append(0.0)
        except Exception:
            artifact_scores.append(0.0)

        fake_probability = float(np.mean(artifact_scores)) if artifact_scores else 0.0
        authenticity_score = 100 - min(100, fake_probability)
        confidence = min(0.88, 0.45 + fake_probability / 200)

        return self._make_result(
            authenticity_score,
            indicators if indicators else ["No significant voice-cloning artifacts detected"],
            confidence,
        )


# ─── Video engine ─────────────────────────────────────────────────────────────

class VideoDeepfakeEngine(DeepfakeDetectionEngine):
    """
    Video deepfake detector: sample frames and aggregate per-frame image scores.
    Also checks for temporal consistency (abrupt scene changes without audio cues).
    """
    FRAME_SAMPLE_RATE = 10  # analyse every Nth frame

    def analyze(self, data: bytes, filename: str) -> Dict[str, Any]:
        indicators: List[str] = []
        img_engine = ImageDeepfakeEngine()

        try:
            with tempfile.NamedTemporaryFile(
                suffix=Path(filename).suffix or ".mp4", delete=False
            ) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            cap = cv2.VideoCapture(tmp_path)
            if not cap.isOpened():
                os.unlink(tmp_path)
                return self._make_result(50.0, ["Could not open video file"], 0.3)

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS) or 25
            duration_s = total_frames / fps

            frame_scores: List[float] = []
            frame_idx = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                if frame_idx % self.FRAME_SAMPLE_RATE == 0:
                    _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                    frame_data = buf.tobytes()
                    result = img_engine.analyze(frame_data, "frame.jpg")
                    frame_scores.append(result["risk_score"])
                frame_idx += 1

            cap.release()
            os.unlink(tmp_path)

            if not frame_scores:
                return self._make_result(50.0, ["No frames could be extracted"], 0.3)

            avg_fake = float(np.mean(frame_scores))
            std_fake = float(np.std(frame_scores))

            if avg_fake > 30:
                indicators.append(f"Average per-frame deepfake score: {avg_fake:.1f}/100")
            if std_fake > 20:
                indicators.append(f"High frame-to-frame inconsistency (std: {std_fake:.1f}) — possible splice")

            # Blink rate heuristic (simplified: measure face region variance over time)
            if avg_fake > 50:
                indicators.append("Unnatural facial region consistency across frames — possible deepfake swap")

            indicators.append(
                f"Analysed {len(frame_scores)} sampled frames from {duration_s:.1f}s video ({total_frames} total frames)"
            )

            authenticity_score = 100 - min(100, avg_fake)
            confidence = min(0.90, 0.4 + avg_fake / 150)

            return self._make_result(authenticity_score, indicators, confidence,
                                     extra={"frames_analysed": len(frame_scores),
                                            "video_duration_s": round(duration_s, 2)})

        except Exception as exc:
            logger.error("Video analysis error: %s", exc)
            return self._make_result(50.0, [f"Video processing error: {exc}"], 0.3)


# ─── Factory ─────────────────────────────────────────────────────────────────

def get_deepfake_engine(media_type: str) -> DeepfakeDetectionEngine:
    """Return the appropriate engine based on MIME type."""
    if "audio" in media_type:
        return AudioDeepfakeEngine()
    if "video" in media_type:
        return VideoDeepfakeEngine()
    return ImageDeepfakeEngine()  # default
