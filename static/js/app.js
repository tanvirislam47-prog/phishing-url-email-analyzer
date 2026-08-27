document.addEventListener("DOMContentLoaded", () => {
    const navToggle = document.querySelector(".nav-toggle");
    const navigation = document.querySelector("#primary-navigation");

    if (navToggle && navigation) {
        navToggle.addEventListener("click", () => {
            const isOpen = navToggle.getAttribute("aria-expanded") === "true";
            navToggle.setAttribute("aria-expanded", String(!isOpen));
            navigation.classList.toggle("is-open", !isOpen);
        });
    }

    const sampleButton = document.querySelector("#sample-email");
    const emailForm = document.querySelector("#email-form");

    if (sampleButton && emailForm) {
        sampleButton.addEventListener("click", () => {
            const values = {
                id_sender: "security@example.invalid",
                id_reply_to: "reply@example.invalid",
                id_subject: "Please verify your account",
                id_body: "Hello,\n\nWe noticed an unusual sign-in. Please review your account through the official website you normally use.\n\nRegards,\nSecurity Team",
                id_attachment_names: "",
            };

            Object.entries(values).forEach(([id, value]) => {
                const field = document.getElementById(id);
                if (field) field.value = value;
            });
        });
    }
});
