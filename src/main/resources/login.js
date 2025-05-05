document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM fully loaded");

  document
    .getElementById("login-form")
    .addEventListener("submit", async function (event) {
      event.preventDefault(); // Prevent default form submission

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;

      // Generate a unique session ID
      const sessionId = `session-${Date.now()}-${Math.floor(
        Math.random() * 1000
      )}`;

      const requestData = JSON.stringify({ username, password, sessionId });

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

          // Redirect to the chat page
          window.location.href = "chat.html";
        } else {
          alert("Invalid username or password.");
        }
      } catch (error) {
        console.error("Fetch error:", error);
      }
    });
});
