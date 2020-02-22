$(document).ready(function() {
    // Getting references to our form and inputs
    var loginForm = $("form.login");
    var emailInput = $("input#email-input");
    var passwordInput = $("input#password-input");
    // var charityInput = $("input#charity-input");
    var charityInput = "";
    console.log(charityInput);
    // When the form is submitted, we validate there's an email and password entered
    loginForm.on("submit", function(event) {
      event.preventDefault();
      if(charityInput !== "") {
        var userData = {
          email: emailInput.val().trim(),
          password: passwordInput.val().trim(),
          charityKey: charityInput.val().trim()
        };
      }
      else {
        var userData = {
          email: emailInput.val().trim(),
          password: passwordInput.val().trim(),
        };
      }
  
      if (!userData.email || !userData.password) {
        return;
      }
  
      // If we have an email and password we run the loginUser function and clear the form
      loginUser(userData.email, userData.password, userData.charityKey);
      emailInput.val("");
      passwordInput.val("");
      // charityInput.val("");
    });
  
    // loginUser does a post to our "api/login" route and if successful, redirects us the the members page
    function loginUser(email, password, charityKey) {
      $.post("/api/login", {
        email: email,
        password: password,
        charityKey: charityKey
      })
        .then(function() {
          console.log("log")
          window.location.replace("/user");
          // If there's an error, log the error
        })
        .catch(function(err) {
          console.log(err);
        });
    }
  });