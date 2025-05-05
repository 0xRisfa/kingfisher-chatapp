document
  .getElementById("register-form")
  .addEventListener("submit", async function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

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
        body: JSON.stringify({ username, password }),
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
