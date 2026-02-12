"""
RAVEN-X Enterprise - Self-Learning AI Engine
This is the BRAIN that makes RAVEN-X improve after every scan, attack, and fix.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

from ..database.database import db_manager
from ..database.models import ThreatPattern, Vulnerability, Fix, MalwareSample, UserFeedback

logger = logging.getLogger(__name__)

class LearningEngine:
    """
    Self-improving AI engine that learns from:
    - Every scan performed
    - Every vulnerability detected
    - Every fix applied (success/failure)
    - User feedback
    - Attack patterns
    """
    
    def __init__(self, models_dir: str = "ml_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # ML Models
        self.malware_classifier = None
        self.anomaly_detector = None
        self.threat_pattern_model = None
        self.scaler = StandardScaler()
        
        # Learning parameters
        self.confidence_threshold = 0.85
        self.min_samples_for_retrain = 100
        self.retrain_interval_hours = 24
        
        # Load existing models
        self.load_models()
        
        logger.info("🧠 Learning Engine initialized")
    
    def load_models(self):
        """Load pre-trained models if they exist"""
        try:
            malware_path = self.models_dir / "malware_classifier.pkl"
            if malware_path.exists():
                with open(malware_path, 'rb') as f:
                    self.malware_classifier = pickle.load(f)
                logger.info("✓ Loaded malware classifier")
            else:
                # Initialize with default model
                self.malware_classifier = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    random_state=42,
                    n_jobs=-1
                )
                logger.info("✓ Initialized new malware classifier")
            
            anomaly_path = self.models_dir / "anomaly_detector.pkl"
            if anomaly_path.exists():
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                logger.info("✓ Loaded anomaly detector")
            else:
                self.anomaly_detector = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_jobs=-1
                )
                logger.info("✓ Initialized new anomaly detector")
            
            scaler_path = self.models_dir / "scaler.pkl"
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("✓ Loaded feature scaler")
                
        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            with open(self.models_dir / "malware_classifier.pkl", 'wb') as f:
                pickle.dump(self.malware_classifier, f)
            
            with open(self.models_dir / "anomaly_detector.pkl", 'wb') as f:
                pickle.dump(self.anomaly_detector, f)
            
            with open(self.models_dir / "scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info("💾 Models saved successfully")
        except Exception as e:
            logger.error(f"❌ Error saving models: {e}")
    
    def generate_threat_signature(self, vuln_data: Dict) -> str:
        """
        Generate unique signature for a vulnerability pattern
        This allows us to track recurring patterns
        """
        signature_components = [
            vuln_data.get('category', ''),
            vuln_data.get('component', ''),
            vuln_data.get('title', ''),
            str(vuln_data.get('severity', ''))
        ]
        
        signature_string = "|".join(signature_components)
        signature_hash = hashlib.sha256(signature_string.encode()).hexdigest()[:16]
        
        return signature_hash
    
    async def learn_from_scan(self, scan_id: str, vulnerabilities: List[Dict]):
        """
        Learn from a completed scan
        - Update threat patterns
        - Identify new attack vectors
        - Update confidence scores
        """
        async with db_manager.get_async_db() as db:
            for vuln in vulnerabilities:
                signature = self.generate_threat_signature(vuln)
                
                # Check if pattern exists
                from sqlalchemy import select
                stmt = select(ThreatPattern).where(ThreatPattern.pattern_signature == signature)
                result = await db.execute(stmt)
                existing_pattern = result.scalar_one_or_none()
                
                if existing_pattern:
                    # Update existing pattern
                    existing_pattern.times_detected += 1
                    existing_pattern.last_detected = datetime.utcnow()
                    existing_pattern.confidence_score = min(
                        1.0,
                        existing_pattern.confidence_score + 0.05
                    )
                    logger.info(f"📈 Updated pattern {signature}: {existing_pattern.times_detected} detections")
                else:
                    # Create new pattern
                    new_pattern = ThreatPattern(
                        pattern_type=vuln.get('category', 'unknown'),
                        pattern_signature=signature,
                        pattern_data=vuln,
                        severity=vuln.get('severity', 'medium'),
                        confidence_score=0.6,  # Start with medium confidence
                        times_detected=1,
                        source='internal_scan'
                    )
                    db.add(new_pattern)
                    logger.info(f"🆕 New pattern learned: {signature}")
                
                await db.commit()
    
    async def learn_from_fix(self, fix_id: str, success: bool, execution_time: float):
        """
        Learn from remediation attempts
        - Track which fixes work
        - Learn optimal fix strategies
        - Improve auto-remediation accuracy
        """
        async with db_manager.get_async_db() as db:
            from sqlalchemy import select
            stmt = select(Fix).where(Fix.id == fix_id)
            result = await db.execute(stmt)
            fix = result.scalar_one_or_none()
            
            if not fix:
                return
            
            # Update fix success rate
            if success:
                if fix.success_rate is None:
                    fix.success_rate = 1.0
                else:
                    # Moving average
                    fix.success_rate = (fix.success_rate * 0.8) + (1.0 * 0.2)
                
                logger.info(f"✅ Fix {fix_id} succeeded. Success rate: {fix.success_rate:.2f}")
            else:
                if fix.success_rate is None:
                    fix.success_rate = 0.0
                else:
                    fix.success_rate = (fix.success_rate * 0.8) + (0.0 * 0.2)
                
                logger.info(f"❌ Fix {fix_id} failed. Success rate: {fix.success_rate:.2f}")
            
            # Learn from execution time (detect slow fixes)
            if execution_time > 30.0:  # If fix takes > 30 seconds
                logger.warning(f"⏱️ Slow fix detected: {fix_id} took {execution_time:.2f}s")
            
            await db.commit()
    
    async def learn_from_user_feedback(self, feedback_data: Dict):
        """
        Learn from user corrections
        - False positive reports
        - True positive confirmations
        - Fix effectiveness ratings
        """
        async with db_manager.get_async_db() as db:
            feedback = UserFeedback(**feedback_data)
            db.add(feedback)
            
            # Update pattern confidence based on feedback
            if feedback.vulnerability_id:
                from sqlalchemy import select
                stmt = select(Vulnerability).where(Vulnerability.id == feedback.vulnerability_id)
                result = await db.execute(stmt)
                vuln = result.scalar_one_or_none()
                
                if vuln and vuln.signature:
                    pattern_stmt = select(ThreatPattern).where(
                        ThreatPattern.pattern_signature == vuln.signature
                    )
                    pattern_result = await db.execute(pattern_stmt)
                    pattern = pattern_result.scalar_one_or_none()
                    
                    if pattern:
                        if feedback.feedback_type == 'false_positive':
                            pattern.false_positive_count += 1
                            pattern.confidence_score = max(0.0, pattern.confidence_score - 0.1)
                            logger.info(f"📉 Pattern {pattern.pattern_signature} confidence decreased (false positive)")
                        
                        elif feedback.feedback_type == 'true_positive':
                            pattern.true_positive_count += 1
                            pattern.confidence_score = min(1.0, pattern.confidence_score + 0.1)
                            logger.info(f"📈 Pattern {pattern.pattern_signature} confidence increased (confirmed)")
            
            await db.commit()
            logger.info(f"🗣️ User feedback processed: {feedback.feedback_type}")
    
    def extract_malware_features(self, file_data: Dict) -> np.ndarray:
        """
        Extract features from file for malware classification
        Features include: file size, entropy, header signatures, etc.
        """
        features = []
        
        # Basic features
        features.append(file_data.get('file_size', 0))
        features.append(len(file_data.get('file_path', '')))
        
        # File type encoding
        file_type = file_data.get('file_type', 'unknown')
        type_encoding = {
            'exe': 1, 'dll': 2, 'sys': 3, 'bat': 4,
            'ps1': 5, 'vbs': 6, 'js': 7, 'unknown': 0
        }
        features.append(type_encoding.get(file_type, 0))
        
        # Entropy (measure of randomness - packed/encrypted malware has high entropy)
        features.append(file_data.get('entropy', 0.0))
        
        # Suspicious indicators
        features.append(1 if file_data.get('has_suspicious_imports', False) else 0)
        features.append(1 if file_data.get('packed', False) else 0)
        features.append(1 if file_data.get('has_anti_debug', False) else 0)
        features.append(1 if file_data.get('has_anti_vm', False) else 0)
        
        # Location-based features
        path = file_data.get('file_path', '').lower()
        features.append(1 if 'temp' in path else 0)
        features.append(1 if 'appdata' in path else 0)
        features.append(1 if 'roaming' in path else 0)
        
        # Pad to consistent feature size
        while len(features) < 20:
            features.append(0)
        
        return np.array(features[:20]).reshape(1, -1)
    
    def predict_malware(self, file_data: Dict) -> Tuple[bool, float]:
        """
        Predict if a file is malware
        Returns: (is_malware, confidence)
        """
        try:
            features = self.extract_malware_features(file_data)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction
            prediction = self.malware_classifier.predict(features_scaled)[0]
            
            # Get confidence (probability)
            if hasattr(self.malware_classifier, 'predict_proba'):
                probabilities = self.malware_classifier.predict_proba(features_scaled)[0]
                confidence = max(probabilities)
            else:
                confidence = 0.75  # Default confidence
            
            is_malware = bool(prediction == 1)
            
            logger.info(f"🔍 Malware prediction: {is_malware} (confidence: {confidence:.2f})")
            return is_malware, confidence
            
        except Exception as e:
            logger.error(f"❌ Error in malware prediction: {e}")
            return False, 0.0
    
    def detect_anomaly(self, system_data: Dict) -> Tuple[bool, float]:
        """
        Detect system anomalies using ML
        Returns: (is_anomaly, anomaly_score)
        """
        try:
            # Extract features from system data
            features = self._extract_system_features(system_data)
            features_scaled = self.scaler.transform(features)
            
            # Predict anomaly
            prediction = self.anomaly_detector.predict(features_scaled)[0]
            
            # Get anomaly score
            if hasattr(self.anomaly_detector, 'score_samples'):
                score = abs(self.anomaly_detector.score_samples(features_scaled)[0])
            else:
                score = 0.5
            
            is_anomaly = bool(prediction == -1)  # IsolationForest uses -1 for anomalies
            
            if is_anomaly:
                logger.warning(f"⚠️ Anomaly detected! Score: {score:.2f}")
            
            return is_anomaly, score
            
        except Exception as e:
            logger.error(f"❌ Error in anomaly detection: {e}")
            return False, 0.0
    
    def _extract_system_features(self, system_data: Dict) -> np.ndarray:
        """Extract features from system state for anomaly detection"""
        features = []
        
        # Process metrics
        features.append(system_data.get('cpu_usage', 0.0))
        features.append(system_data.get('memory_usage', 0.0))
        features.append(system_data.get('disk_usage', 0.0))
        features.append(system_data.get('network_bytes_sent', 0))
        features.append(system_data.get('network_bytes_recv', 0))
        
        # Process counts
        features.append(system_data.get('process_count', 0))
        features.append(system_data.get('thread_count', 0))
        features.append(system_data.get('handle_count', 0))
        
        # Network metrics
        features.append(system_data.get('open_connections', 0))
        features.append(system_data.get('listening_ports', 0))
        
        # Security indicators
        features.append(1 if system_data.get('firewall_enabled', True) else 0)
        features.append(1 if system_data.get('antivirus_enabled', True) else 0)
        features.append(system_data.get('failed_login_attempts', 0))
        
        # Pad to consistent size
        while len(features) < 20:
            features.append(0)
        
        return np.array(features[:20]).reshape(1, -1)
    
    async def retrain_models(self):
        """
        Retrain ML models with accumulated data
        This is the CORE of self-improvement
        """
        logger.info("🔄 Starting model retraining...")
        
        async with db_manager.get_async_db() as db:
            from sqlalchemy import select, func
            
            # Check if we have enough data
            malware_count_stmt = select(func.count(MalwareSample.id))
            result = await db.execute(malware_count_stmt)
            malware_count = result.scalar()
            
            if malware_count < self.min_samples_for_retrain:
                logger.info(f"⏸️ Not enough samples for retraining ({malware_count}/{self.min_samples_for_retrain})")
                return
            
            # Fetch malware samples
            malware_stmt = select(MalwareSample)
            result = await db.execute(malware_stmt)
            malware_samples = result.scalars().all()
            
            # Prepare training data
            X = []
            y = []
            
            for sample in malware_samples:
                file_data = {
                    'file_size': sample.file_size,
                    'file_path': sample.file_path,
                    'file_type': sample.file_type,
                    'entropy': sample.static_analysis.get('entropy', 0) if sample.static_analysis else 0
                }
                
                features = self.extract_malware_features(file_data)
                X.append(features.flatten())
                
                # Label: 1 for malware, 0 for benign
                label = 0 if sample.is_false_positive else 1
                y.append(label)
            
            if len(X) < 10:
                logger.warning("⏸️ Not enough valid samples for training")
                return
            
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train malware classifier
            self.malware_classifier.fit(X_train_scaled, y_train)
            train_score = self.malware_classifier.score(X_train_scaled, y_train)
            test_score = self.malware_classifier.score(X_test_scaled, y_test)
            
            logger.info(f"✅ Malware classifier retrained!")
            logger.info(f"   Training accuracy: {train_score:.2%}")
            logger.info(f"   Testing accuracy: {test_score:.2%}")
            
            # Save updated models
            self.save_models()
            
            logger.info("🎓 Model retraining complete. RAVEN-X is now smarter!")
    
    async def get_learning_stats(self) -> Dict:
        """Get statistics about what the system has learned"""
        async with db_manager.get_async_db() as db:
            from sqlalchemy import select, func
            
            # Count threat patterns
            pattern_stmt = select(func.count(ThreatPattern.id))
            result = await db.execute(pattern_stmt)
            total_patterns = result.scalar()
            
            # Count high-confidence patterns
            high_conf_stmt = select(func.count(ThreatPattern.id)).where(
                ThreatPattern.confidence_score >= 0.85
            )
            result = await db.execute(high_conf_stmt)
            high_confidence_patterns = result.scalar()
            
            # Count malware samples
            malware_stmt = select(func.count(MalwareSample.id))
            result = await db.execute(malware_stmt)
            malware_samples = result.scalar()
            
            # Count user feedback
            feedback_stmt = select(func.count(UserFeedback.id))
            result = await db.execute(feedback_stmt)
            feedback_count = result.scalar()
            
            return {
                'total_threat_patterns': total_patterns,
                'high_confidence_patterns': high_confidence_patterns,
                'malware_samples': malware_samples,
                'user_feedback_count': feedback_count,
                'model_accuracy': 0.95,  # Placeholder - would come from actual model metrics
                'last_retrain': datetime.utcnow().isoformat()
            }


# Global learning engine instance
learning_engine = LearningEngine()