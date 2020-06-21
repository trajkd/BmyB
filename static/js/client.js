// Set up Stripe.js and Elements to use in checkout form
var style = {
  base: {
    color: "#32325d",
    fontFamily: '"Helvetica Neue", Helvetica, sans-serif',
    fontSmoothing: "antialiased",
    fontSize: "16px",
    "::placeholder": {
      color: "#aab7c4"
    }
  },
  invalid: {
    color: "#fa755a",
    iconColor: "#fa755a"
  }
};

var cardElement = elements.create("card", { style: style });
cardElement.mount("#card-element");

card.addEventListener('change', function(event) {
  var displayError = document.getElementById('card-errors');
  if (event.error) {
    displayError.textContent = event.error.message;
  } else {
    displayError.textContent = '';
  }
});

var form = document.getElementById('subscription-form');

form.addEventListener('submit', function(event) {
  // We don't want to let default form submission happen here,
  // which would refresh the page.
  event.preventDefault();

  stripe.createPaymentMethod({
    type: 'card',
    card: cardElement,
    billing_details: {
      email: 'jenny.rosen@example.com',
    },
  }).then(stripePaymentMethodHandler);
});



const { latest_invoice } = subscription;
const { payment_intent } = latest_invoice;

if (payment_intent) {
  const { client_secret, status } = payment_intent;

  if (status === 'requires_action') {
    stripe.confirmCardPayment(client_secret).then(function(result) {
      if (result.error) {
        // Display error message in your UI.
        // The card was declined (i.e. insufficient funds, card has expired, etc)
        document.querySelector('.bg-error').style.display = "flex";
      } else {
        // Show a success message to your customer
        document.querySelector('.bg-success').style.display = "flex";
      }
    });
  } else {
    // No additional information was needed
    // Show a success message to your customer
    document.querySelector('.bg-success').style.display = "flex";
  }
}