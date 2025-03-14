console.log("✅ JS загружен!");

// DOM загружен
document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ DOM полностью загружен!");

    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");
    const loginBtn = document.getElementById("loginBtn");
    const registerBtn = document.getElementById("registerBtn");
    const closeButtons = document.querySelectorAll(".close");

    // Скрываем модальные окна при загрузке (важно!)
    if (loginModal) loginModal.style.display = "none";
    if (registerModal) registerModal.style.display = "none";

    function openModal(modal) {
        if (modal) modal.style.display = "flex";
    }

    function closeModal(modal) {
        if (modal) modal.style.display = "none";
    }

    // Открытие модальных окон по нажатию кнопок
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

    // Закрытие модальных окон (кнопка "×")
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

            const username = document.getElementById("new-username").value.trim();
            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("new-password").value.trim();

            const usernameRegex = /^[a-zA-Z0-9]{6,}$/;
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/;

            if (!usernameRegex.test(username)) return alert("Имя пользователя должно содержать минимум 6 символов (только буквы и цифры).");
            if (!emailRegex.test(email)) return alert("Введите корректный e-mail.");
            if (!passwordRegex.test(password)) return alert("Пароль должен содержать минимум 8 символов, одну заглавную букву, одну строчную и один спецсимвол.");

            fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, email, password })
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) window.location.reload();
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
                    window.location.href = "/";
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
            window.location.href = "/logout";  // Просто переходим на /logout
        });
    }
});

document.getElementById("reportForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const url = document.getElementById("reportUrl").value.trim();

    fetch("/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
    });
});


document.getElementById("url").addEventListener("input", function () {
    const url = this.value.trim();

    if (!url) return;

    fetch("/complaints", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.count >= 5) {
            alert(`⚠️ Внимание! Этот сайт помечен как опасный (${data.count} жалоб)`);
        }
    });
});
