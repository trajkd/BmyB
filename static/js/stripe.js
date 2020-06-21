var publicKey = 'pk_test_FUHWZOulQXklzeRKDX0jGSNq00DDlKcum9';

var stripe;

var stripeElements = function(publicKey) {
  stripe = Stripe(publicKey);
  var elements = stripe.elements();

  // Element styles
  var style = {
    base: {
      fontSize: '16px',
      color: '#32325d',
      fontFamily:
        '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif',
      fontSmoothing: 'antialiased',
      '::placeholder': {
        color: 'rgba(0,0,0,0.4)'
      }
    }
  };

  var card = elements.create('card', { style: style });

  card.mount('#card-element');

  // Element focus ring
  card.on('focus', function() {
    var el = document.getElementById('card-element');
    el.classList.add('focused');
  });

  card.on('blur', function() {
    var el = document.getElementById('card-element');
    el.classList.remove('focused');
  });

  document.querySelector('#submit').addEventListener('click', function(evt) {
    evt.preventDefault();
    changeLoadingState(true);
    // Initiate payment
    createPaymentMethodAndCustomer(stripe, card);
  });
};

stripeElements(publicKey);

function showCardError(error) {
  changeLoadingState(false);
  // The card was declined (i.e. insufficient funds, card has expired, etc)
  var errorMsg = document.querySelector('#error');
  errorMsg.style.display = "flex";
  document.querySelector('.error-status').textContent = error.message;
  close = document.querySelectorAll('.close')
  for (var i = 0 ; i < close.length; i++) {
	close[i].addEventListener("click", function() {
	  errorMsg.style.display = "none";
	});
  }
  setTimeout(function() {
    document.querySelector('.error-status').textContent = '';
    errorMsg.style.display = "none";
  }, 8000);
}

var createPaymentMethodAndCustomer = function(stripe, card) {
  var cardholderEmail = document.querySelector('#inputEmail').value;
  stripe
    .createPaymentMethod('card', card, {
      billing_details: {
        email: cardholderEmail
      }
    })
    .then(function(result) {
      if (result.error) {
        showCardError(result.error);
      } else {
        createCustomer(result.paymentMethod.id, cardholderEmail);
      }
    });
};

async function createCustomer(paymentMethod, cardholderEmail) {
  return fetch('/create-customer', {
    method: 'post',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: cardholderEmail,
      payment_method: paymentMethod
    })
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Something went wrong');
      }
    })
    .then(subscription => {
      handleSubscription(subscription);
      // Display subscribed successfully
      // window.location.href = '/subscription/'
      orderComplete(subscription);
    })
    .catch(function() {
    	alreadySubscribed();
    });
}

function handleSubscription(subscription) {
  const latest_invoice = subscription['latest_invoice'];
  console.log(subscription)
  const payment_intent = subscription['latest_invoice'].payment_intent;

  if (payment_intent) {
    const { client_secret, status } = payment_intent;

    if (status === 'requires_action') {
      stripe.confirmCardPayment(client_secret).then(function(result) {
        if (result.error) {
          // Display error message in your UI.
          // The card was declined (i.e. insufficient funds, card has expired, etc)
          showCardError(result.error);
        } else {
          // Show a success message to your customer
          confirmSubscription(subscription.id);
        }
      });
    } else {
      // No additional information was needed
      // Show a success message to your customer
      orderComplete(subscription);
    }
  } else {
    orderComplete(subscription);
  }
}

function isJson(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}

function confirmSubscription(subscriptionId) {
  return fetch('/signupform', {
    method: 'post',
    headers: {
      'Content-type': 'application/json'
    },
    body: JSON.stringify({
      subscriptionId: subscriptionId
    })
  })
    .then(function(response) {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Something went wrong');
      }
    })
    .then(function(subscription) {
      orderComplete(subscription);
    })
    .catch(function() {
    	fuckOff();
    });
}

function alreadySubscribed() {
  changeLoadingState(false);
  // The card was declined (i.e. insufficient funds, card has expired, etc)
  var errorMsg = document.querySelector('#error');
  errorMsg.style.display = "flex";
  document.querySelector('.error-status').textContent = "You have already subscribed.";
  close = document.querySelectorAll('.close')
  for (var i = 0 ; i < close.length; i++) {
	close[i].addEventListener("click", function() {
	  errorMsg.style.display = "none";
	});
  }
  setTimeout(function() {
    document.querySelector('.error-status').textContent = '';
    errorMsg.style.display = "none";
  }, 8000);
}

/* ------- Post-payment helpers ------- */

/* Shows a success / error message when the payment is complete */
var orderComplete = function(subscription) {
  changeLoadingState(false);
  var subscriptionJson = subscription;
  // document.querySelectorAll('.payment-view').forEach(function(view) {
  //   view.classList.add('hidden');
  // });
  // document.querySelectorAll('.completed-view').forEach(function(view) {
  //   view.classList.remove('hidden');
  // });
  document.querySelector('#success').style.display = "flex";
  document.querySelector('.order-status').textContent = "Subscription " + subscription.status;
  //document.querySelector('code').textContent = subscriptionJson;
};

// Show a spinner on subscription submission
var changeLoadingState = function(isLoading) {
  if (isLoading) {
    document.querySelector('#spinner').classList.add('loading');
    document.querySelector('button').disabled = true;

    document.querySelector('#button-text').classList.add('hidden');
  } else {
    document.querySelector('button').disabled = false;
    document.querySelector('#spinner').classList.remove('loading');
    document.querySelector('#button-text').classList.remove('hidden');
  }
};

document.querySelector('#catalog').addEventListener("click", function() {
	window.location.href = "/";
});