from models.user import db
from datetime import datetime
from sqlalchemy import desc

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    youtube_id = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('videos', lazy=True))
    annotations = db.relationship('Annotation', backref='video', lazy=True, cascade='all, delete-orphan')

    @classmethod
    def get_all_videos(cls):
        return cls.query.order_by(desc(cls.created_at)).all()
    
    @classmethod
    def get_user_videos(cls, user_id):
        return cls.query.filter_by(user_id=user_id).order_by(desc(cls.created_at)).all()

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'youtube_id': self.youtube_id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'annotations': [ann.to_dict() for ann in self.annotations]
        }

class Annotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(10), nullable=False)  # Format: MM:SS
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('annotations', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp,
            'video_id': self.video_id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }
