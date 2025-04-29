from app import db

class Contacto(db.Model):
    __tablename__ = 'contacto'
    
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    mensaje = db.Column(db.Text, nullable=False)
    fecha_creacion = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<Contacto {self.email}>'