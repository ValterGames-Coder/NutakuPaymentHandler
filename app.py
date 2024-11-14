from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from datetime import datetime

app = Flask(__name__)

# Configuring the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///payments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class Payment(db.Model):
    id = db.Column(db.String, primary_key=True)
    appId = db.Column(db.String)  # App ID
    userId = db.Column(db.String)  # Player ID (me)
    status = db.Column(db.Integer)
    callbackUrl = db.Column(db.String)
    finishPageUrl = db.Column(db.String)
    message = db.Column(db.String)
    paymentItems = db.relationship('PaymentItem', backref='payment', lazy=True)
    orderedTime = db.Column(db.DateTime)
    executedTime = db.Column(db.DateTime)
    transactionUrl = db.Column(db.String)

class PaymentItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    itemId = db.Column(db.String)
    itemName = db.Column(db.String)
    unitPrice = db.Column(db.String)
    quantity = db.Column(db.String)
    imageUrl = db.Column(db.String)
    description = db.Column(db.String)

# Create the database
with app.app_context():
    db.create_all()

@app.route('/callback')
def callback():
    response_data = {
        "response_code": "OK"
    }

    return jsonify(response_data), 200

@app.route('/social/rest/payment/<player_id>/<self>/<app_id>', methods=['POST'])
def process_payment(player_id, self, app_id):
    data = request.get_json()

    # Generate a unique payment ID
    payment_id = str(uuid.uuid4())
    ordered_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Example status and message
    status = 1
    message = "Payment processed successfully."

    # Save payment data to the database
    payment = Payment(id=payment_id, userId=player_id, appId=app_id, status=status, message=message, orderedTime=ordered_time)
    db.session.add(payment)
    db.session.commit()

    # Example of adding an item to the payment
    item = PaymentItem(payment_id=payment_id, item_id="ex101", item_name="Meat", unit_price="300", quantity="1",
                       image_url="http://example.com/ex101.jpg", description="Description of meat")
    db.session.add(item)
    db.session.commit()

    response_data = {
        "entry": {
            "paymentId": payment_id,
            "status": status,
            "transactionUrl": f"http://[payment server]/application/-/purchase/=/payment_id={payment_id}",
            "orderedTime": ordered_time
        }
    }

    return jsonify(response_data), 201

@app.route('/social/rest/payment/<payment_id>/<self>/<app_id>', methods=['GET'])
def get_payment(payment_id, app_id):
    payment = Payment.query.filter_by(id=payment_id).first()

    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    items = PaymentItem.query.filter_by(payment_id=payment_id).all()
    payment_items = [{
        "itemId": item.itemId,
        "itemName": item.itemName,
        "unitPrice": item.unitPrice,
        "quantity": item.quantity,
        "imageUrl": item.image_url,
        "description": item.description
    } for item in items]

    response_data = {
        "entry": [{
            "paymentId": payment.id,
            "status": payment.status,
            "message": payment.message,
            "paymentItems": payment_items
        }]
    }

    return jsonify(response_data), 200


if __name__ == '__main__':
    app.run(debug=True)