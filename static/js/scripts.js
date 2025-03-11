console.log("✅ JS загружен!");

// Проверка на лишние вызовы
document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ DOM полностью загружен!");

    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");

    console.log("⏳ Скрываем модальные окна...");
    loginModal.style.display = "none";
    registerModal.style.display = "none";
});


document.addEventListener("DOMContentLoaded", function () {
    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");
    const loginBtn = document.getElementById("loginBtn");
    const registerBtn = document.getElementById("registerBtn");
    const closeButtons = document.querySelectorAll(".close");

    // Скрываем окна при загрузке
    loginModal.style.display = "none";
    registerModal.style.display = "none";

    function openModal(modal) {
        modal.style.display = "flex";
    }

    function closeModal(modal) {
        modal.style.display = "none";
    }

    loginBtn.addEventListener("click", function () {
        openModal(loginModal);
    });

    registerBtn.addEventListener("click", function () {
        openModal(registerModal);
    });

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

    // AJAX Регистрация
    const registerForm = document.getElementById("register-form");
    if (registerForm) {
        registerForm.addEventListener("submit", function (event) {
            event.preventDefault();

            fetch("/register", {
                method: "POST",
                body: new FormData(this),
            })
            .then(response => response.text())
            .then(text => {
                if (text === "success") {
                    window.location.href = "/welcome";
                } else {
                    alert("Ошибка регистрации! Пользователь уже существует.");
                }
            });
        });
    }

    // AJAX Вход
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
        loginForm.addEventListener("submit", function (event) {
            event.preventDefault();

            fetch("/login", {
                method: "POST",
                body: new FormData(this),
            })
            .then(response => response.text())
            .then(text => {
                if (text === "success") {
                    window.location.href = "/dashboard";
                } else {
                    alert("Ошибка входа! Проверьте данные.");
                }
            });
        });
    }
});
