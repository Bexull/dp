console.log("✅ JS загружен!");

// Проверка на лишние вызовы
document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ DOM полностью загружен!");

    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");

    console.log("⏳ Скрываем модальные окна...");
    if (loginModal && registerModal) {
        loginModal.style.display = "none";
        registerModal.style.display = "none";
    }
});

document.addEventListener("DOMContentLoaded", function () {
    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");
    const loginBtn = document.getElementById("loginBtn");
    const registerBtn = document.getElementById("registerBtn");
    const closeButtons = document.querySelectorAll(".close");

    function openModal(modal) {
        modal.style.display = "flex";
    }

    function closeModal(modal) {
        modal.style.display = "none";
    }

    if (loginBtn) {
        loginBtn.addEventListener("click", function () {
            openModal(loginModal);
        });
    }

    if (registerBtn) {
        registerBtn.addEventListener("click", function () {
            openModal(registerModal);
        });
    }

    closeButtons.forEach(button => {
        button.addEventListener("click", function () {
            closeModal(this.closest(".modal"));
        });
    });

    // Закрытие окна при клике на затемненный фон
    window.addEventListener("click", function (event) {
        if (event.target.classList.contains("modal")) {
            closeModal(event.target);
        }
    });

    // Регистрация
    const registerForm = document.getElementById("register-form");
    if (registerForm) {
        registerForm.addEventListener("submit", function (event) {
            event.preventDefault();

            fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: document.getElementById("new-username").value.trim(),
                    password: document.getElementById("new-password").value.trim()
                })
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    location.reload();  // Перезагружаем страницу после успешной регистрации
                }
            });
        });
    }

    // Вход
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
        loginForm.addEventListener("submit", function (event) {
            event.preventDefault();

            fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: document.getElementById("username").value.trim(),
                    password: document.getElementById("password").value.trim()
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();  // Перезагружаем страницу после успешного входа
                } else {
                    alert("Ошибка входа! Проверьте данные.");
                }
            });
        });
    }

    // Выход
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", function () {
            fetch("/logout", { method: "POST" })
            .then(() => {
                location.reload();  // Обновляем страницу после выхода
            });
        });
    }
});
