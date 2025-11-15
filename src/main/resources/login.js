document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM fully loaded");

  const loginForm = document.getElementById("login-form");
  const submitButton = loginForm.querySelector('button[type="submit"]');
  const originalButtonText = submitButton.textContent;

  loginForm.addEventListener("submit", async function (event) {
    event.preventDefault(); // Prevent default form submission

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) {
      if (typeof showToast !== 'undefined') {
        showToast("Please fill in all fields", "error");
      } else {
        alert("Please fill in all fields");
      }
      return;
    }

    // Generate a unique session ID
    const sessionId = `session-${Date.now()}-${Math.floor(
      Math.random() * 1000
    )}`;

    const requestData = JSON.stringify({ username, password, sessionId });

    // Show loading state
    if (typeof showLoading !== 'undefined') {
      showLoading("Logging in...");
    }
    submitButton.disabled = true;
    submitButton.innerHTML = '<div class="loading-spinner"></div>';

    try {
      const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: requestData,
      });

      const data = await response.json();

      if (data.success) {
        // Store session ID and username
        sessionStorage.setItem("userSessionId", sessionId);
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("username", username);

        if (typeof showToast !== 'undefined') {
          showToast("Login successful!", "success", 1000);
        }

        // Redirect to the chat page after a brief delay
        setTimeout(() => {
          window.location.href = "chat.html";
        }, 500);
      } else {
        if (typeof hideLoading !== 'undefined') {
          hideLoading();
        }
        submitButton.disabled = false;
        submitButton.textContent = originalButtonText;
        
        if (typeof showToast !== 'undefined') {
          showToast("Invalid username or password", "error");
        } else {
          alert("Invalid username or password.");
        }
      }
    } catch (error) {
      console.error("Fetch error:", error);
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
      submitButton.disabled = false;
      submitButton.textContent = originalButtonText;
      
      if (typeof showToast !== 'undefined') {
        showToast("Connection error. Please try again.", "error");
      } else {
        alert("Connection error. Please try again.");
      }
    }
  });
});
