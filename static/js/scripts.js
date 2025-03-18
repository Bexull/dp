console.log("✅ JS загружен!");

// DOM загружен
document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ DOM полностью загружен!");

    const loginModal = document.getElementById("loginModal");
    const registerModal = document.getElementById("registerModal");
    const loginBtn = document.getElementById("loginBtn");
    const registerBtn = document.getElementById("registerBtn");
    const closeButtons = document.querySelectorAll(".close");

    // Скрываем модальные окна при загрузке
    if (loginModal) loginModal.style.display = "none";
    if (registerModal) registerModal.style.display = "none";

    function openModal(modal) {
        if (modal) modal.style.display = "flex";
    }

    function closeModal(modal) {
        if (modal) modal.style.display = "none";
    }

    // Открытие модальных окон
    if (loginBtn) loginBtn.addEventListener("click", () => openModal(loginModal));
    if (registerBtn) registerBtn.addEventListener("click", () => openModal(registerModal));

    // Закрытие окон
    closeButtons.forEach(button => {
        button.addEventListener("click", function () {
            closeModal(this.closest(".modal"));
        });
    });

    window.addEventListener("click", function (event) {
        if (event.target.classList.contains("modal")) {
            closeModal(event.target);
        }
    });
    window.addEventListener("DOMContentLoaded", () => {
    if (performance.navigation.type === 1) {  // Если страница была перезагружена
        fetch("/", { method: "GET" })  // Отправляем запрос на сервер
            .then(() => {
                document.getElementById("result").textContent = "";
                document.getElementById("url").value = "";
            });
        }
    });




    // Форма регистрации
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

            if (!usernameRegex.test(username)) return alert("Имя пользователя должно содержать минимум 6 символов.");
            if (!emailRegex.test(email)) return alert("Введите корректный e-mail.");
            if (!passwordRegex.test(password)) return alert("Пароль должен содержать минимум 8 символов, включая заглавную букву и спецсимвол.");

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

    // Форма входа
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
            window.location.href = "/logout";
        });
    }

        // Функция очистки всех полей ввода в модальном окне
    function clearModalInputs(modal) {
        if (!modal) return;
        const inputs = modal.querySelectorAll("input");
        inputs.forEach(input => input.value = "");
    }

    // Закрытие окон и очистка полей ввода
    closeButtons.forEach(button => {
        button.addEventListener("click", function () {
            const modal = this.closest(".modal");
            closeModal(modal);
            clearModalInputs(modal);
        });
    });

    window.addEventListener("click", function (event) {
        if (event.target.classList.contains("modal")) {
            closeModal(event.target);
            clearModalInputs(event.target);
        }
    });


    // Смена фона
    const changeBgButton = document.getElementById("changeBgButton");
    let backgrounds = [
        "https://i.gifer.com/9gu9.gif",
        "https://i.gifer.com/1pX9.gif",
    ];
    let currentBgIndex = 0;

    if (changeBgButton) {
        changeBgButton.addEventListener("click", function () {
            currentBgIndex = (currentBgIndex + 1) % backgrounds.length;
            document.body.style.backgroundImage = `url('${backgrounds[currentBgIndex]}')`;
        });
    }

    // Переключение языка
    const languageToggleBtn = document.getElementById("langToggle");

    const translations = {
        ru: {
            check: "Проверить",
            change_bg: "Фон",
            clear_history: "Очистить историю",
            check_url: "Проверка URL",
            logout: "Выйти",
            login: "Войти",
            register: "Регистрация",
            lang_toggle: "Русский",
            check_url_title: "Проверка URL",
            enter_url: "Введите URL:",
            check: "Проверить",
            result: "Результат:",
            report_site: "Пожаловаться на сайт",
            report: "Пожаловаться",
            login_title: "Вход",
            login_username: "Имя пользователя:",
            login_password: "Пароль:",
            login_button: "Войти",
            register_title: "Регистрация",
            register_username: "Имя пользователя:",
            register_email: "E-mail:",
            register_password: "Пароль:",
            register_button: "Регистрация"
        },
        en: {
            check: "Check",
            change_bg: "Change Theme",
            clear_history: "Clear History",
            check_url: "URL Check",
            logout: "Logout",
            login: "Login",
            register: "Sign up",
            lang_toggle: "English",
            check_url_title: "URL Check",
            enter_url: "Enter URL:",
            check: "Check",
            result: "Result:",
            report_site: "Report a Website",
            report: "Report",
            login_title: "Login",
            login_username: "Username:",
            login_password: "Password:",
            login_button: "Login",
            register_title: "Register",
            register_username: "Username:",
            register_email: "E-mail:",
            register_password: "Password:",
            register_button: "Sign Up"
        }
    };

    function updateTexts(lang) {
        if (document.getElementById("checkButton")) {
            document.getElementById("checkButton").textContent = translations[lang].check;
        }
        if (document.getElementById("changeBgButton")) {
            document.getElementById("changeBgButton").textContent = translations[lang].change_bg;
        }
        if (document.getElementById("clearHistory")) {
            document.getElementById("clearHistory").textContent = translations[lang].clear_history;
        }
        if (document.getElementById("check")) {
            document.getElementById("check").textContent = translations[lang].check_url;
        }
        if (document.getElementById("logoutBtn")) {
            document.getElementById("logoutBtn").textContent = translations[lang].logout;
        }
        if (document.getElementById("loginBtn")) {
            document.getElementById("loginBtn").textContent = translations[lang].login;
        }
        if (document.getElementById("registerBtn")) {
            document.getElementById("registerBtn").textContent = translations[lang].register;
        }
        if (document.getElementById("langToggle")) {
            document.getElementById("langToggle").textContent = translations[lang].lang_toggle;
        }
        if (document.getElementById("checkUrlInContainer")) {
            document.getElementById("checkUrlInContainer").textContent = translations[lang].checkUrlInContainer;
        }
        if (document.getElementById("checkUrlInContainer")) {
            document.getElementById("checkUrlInContainer").textContent = translations[lang].check_url_title;
        }
        if (document.getElementById("enterUrlLabel")) {
            document.getElementById("enterUrlLabel").textContent = translations[lang].enter_url;
        }
        if (document.getElementById("checkButton")) {
            document.getElementById("checkButton").textContent = translations[lang].check;
        }
        if (document.getElementById("resultTitle")) {
            document.getElementById("resultTitle").textContent = translations[lang].result;
        }
        if (document.getElementById("reportSiteTitle")) {
            document.getElementById("reportSiteTitle").textContent = translations[lang].report_site;
        }
        if (document.getElementById("reportButton")) {
            document.getElementById("reportButton").textContent = translations[lang].report;
        }
        if (document.getElementById("loginTitle")) {
        document.getElementById("loginTitle").textContent = translations[lang].login_title;
        }
        if (document.getElementById("loginUsernameLabel")) {
            document.getElementById("loginUsernameLabel").textContent = translations[lang].login_username;
        }
        if (document.getElementById("loginPasswordLabel")) {
            document.getElementById("loginPasswordLabel").textContent = translations[lang].login_password;
        }
        if (document.getElementById("loginButton")) {
            document.getElementById("loginButton").textContent = translations[lang].login_button;
        }
        if (document.getElementById("registerTitle")) {
            document.getElementById("registerTitle").textContent = translations[lang].register_title;
        }
        if (document.getElementById("registerUsernameLabel")) {
            document.getElementById("registerUsernameLabel").textContent = translations[lang].register_username;
        }
        if (document.getElementById("registerEmailLabel")) {
            document.getElementById("registerEmailLabel").textContent = translations[lang].register_email;
        }
        if (document.getElementById("registerPasswordLabel")) {
            document.getElementById("registerPasswordLabel").textContent = translations[lang].register_password;
        }
        if (document.getElementById("registerButton")) {
            document.getElementById("registerButton").textContent = translations[lang].register_button;
        }
    }

    // Проверяем, сохранен ли язык в localStorage, если нет — устанавливаем русский
    let savedLang = localStorage.getItem("language") || "ru";
    updateTexts(savedLang);

    if (languageToggleBtn) {
        languageToggleBtn.addEventListener("click", function () {
            let currentLang = localStorage.getItem("language") || "ru";
            let newLang = currentLang === "ru" ? "en" : "ru";
            localStorage.setItem("language", newLang);
            updateTexts(newLang);
        });
    }



    // Очистка истории
//    const clearHistoryBtn = document.getElementById("clearHistory");
//    if (clearHistoryBtn) {
//        clearHistoryBtn.addEventListener("click", function () {
//            fetch("/clear_history", {
//                method: "POST"
//            })
//            .then(response => response.json())
//            .then(data => {
//                if (data.success) {
//                    alert("История успешно очищена!");
//                    location.reload();
//                } else {
//                    alert("Ошибка при очистке истории!");
//                }
//            })
//            .catch(error => alert("Ошибка соединения!"));
//        });
//    }

    // Жалобы на фишинговый сайт
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


});
