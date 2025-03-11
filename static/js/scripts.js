document.addEventListener("DOMContentLoaded", function () {
    let loginModal = document.getElementById("loginModal");
    let registerModal = document.getElementById("registerModal");

    document.getElementById("loginBtn").onclick = function () {
        loginModal.style.display = "block";
    };

    document.getElementById("registerBtn").onclick = function () {
        registerModal.style.display = "block";
    };

    document.querySelectorAll(".close").forEach(function (el) {
        el.onclick = function () {
            loginModal.style.display = "none";
            registerModal.style.display = "none";
        };
    });

    window.onclick = function (event) {
        if (event.target === loginModal) {
            loginModal.style.display = "none";
        }
        if (event.target === registerModal) {
            registerModal.style.display = "none";
        }
    };
});
