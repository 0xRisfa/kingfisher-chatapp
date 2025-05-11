const passwordInput = document.getElementById("password");
const strengthBar = document.getElementById("password-strength-bar");
const reqLength = document.getElementById("req-length");
const reqUpper = document.getElementById("req-upper");
const reqLower = document.getElementById("req-lower");
const reqDigit = document.getElementById("req-digit");
const reqSpecial = document.getElementById("req-special");

passwordInput.addEventListener("input", function () {
  const value = passwordInput.value;
  let strength = 0;

  // Check requirements
  const lengthOK = value.length >= 8;
  const upperOK = /[A-Z]/.test(value);
  const lowerOK = /[a-z]/.test(value);
  const digitOK = /\d/.test(value);
  const specialOK = /[^A-Za-z0-9]/.test(value);

  // Update requirements list
  reqLength.style.color = lengthOK ? "green" : "red";
  reqUpper.style.color = upperOK ? "green" : "red";
  reqLower.style.color = lowerOK ? "green" : "red";
  reqDigit.style.color = digitOK ? "green" : "red";
  reqSpecial.style.color = specialOK ? "green" : "red";

  // Calculate strength
  strength += lengthOK ? 1 : 0;
  strength += upperOK ? 1 : 0;
  strength += lowerOK ? 1 : 0;
  strength += digitOK ? 1 : 0;
  strength += specialOK ? 1 : 0;

  // Update strength bar
  const colors = ["#e53935", "#ff9800", "#fbc02d", "#43a047", "#388e3c"];
  strengthBar.style.width = strength * 20 + "%";
  strengthBar.style.background = colors[strength - 1] || "#e53935";
});

// On form submit, prevent registration if requirements are not met
document
  .getElementById("register-form")
  .addEventListener("submit", async function (event) {
    const value = passwordInput.value;
    if (
      value.length < 8 ||
      !/[A-Z]/.test(value) ||
      !/[a-z]/.test(value) ||
      !/\d/.test(value) ||
      !/[^A-Za-z0-9]/.test(value)
    ) {
      event.preventDefault();
      alert("Password does not meet all requirements.");
      return;
    }

    event.preventDefault();

    const username = document.getElementById("username").value;

    try {
      // Fetch the API base URL from config.json
      const configResponse = await fetch("/config.json");
      if (!configResponse.ok) {
        throw new Error("Failed to load configuration");
      }
      const config = await configResponse.json();
      const apiBaseUrl = config.apiBaseUrl || "http://localhost:3000";

      // Send the registration request
      const response = await fetch(`/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password: value }),
      });

      if (response.ok) {
        alert("Registration successful!");
        window.location.href = "index.html";
      } else {
        alert("Registration failed");
      }
    } catch (error) {
      console.error("Error during registration:", error);
      alert("An error occurred. Please try again later.");
    }
  });
