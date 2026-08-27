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
                id_sender: "security@example.com",
                id_reply_to: "reply@external.example",
                id_subject: "Urgent action required",
                id_body: "Hello,\n\nWe noticed an unusual sign-in. Please click the link below immediately to verify your password and secure your account.\n\nhttps://bit.ly/login\n\nRegards,\nSecurity Team",
                id_attachment_names: "update.docm, instructions.pdf",
            };

            Object.entries(values).forEach(([id, value]) => {
                const field = document.getElementById(id);
                if (field) field.value = value;
            });
        });
    }
});
