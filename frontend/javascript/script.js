const apiBaseUrl = "http://127.0.0.1:5000"; // sua API Flask

// --- Cadastro ---
document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const data = {
    name: document.getElementById("name").value,
    email: document.getElementById("email").value,
    password: document.getElementById("password").value,
    cnpj: document.getElementById("cnpj").value,
    celular: document.getElementById("celular").value
  };

  try {
    const response = await fetch(`${apiBaseUrl}/user`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    const result = await response.json();
    document.getElementById("result").innerText = JSON.stringify(result);
  } catch (err) {
    document.getElementById("result").innerText = "Erro: " + err.message;
  }
});

// --- Login ---
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const data = {
    email: document.getElementById("loginEmail").value,
    password: document.getElementById("loginPassword").value
  };

  try {
    const response = await fetch(`${apiBaseUrl}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    const result = await response.json();
    document.getElementById("result").innerText = JSON.stringify(result);
  } catch (err) {
    document.getElementById("result").innerText = "Erro: " + err.message;
  }
});
