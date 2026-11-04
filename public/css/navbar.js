document.addEventListener("DOMContentLoaded", () => {
    const topbar =
        document.querySelector(".topbar");

    const nav =
        document.querySelector(".topbar .nav");

    const toggle =
        document.querySelector(".mobile-nav-toggle");

    if (!topbar || !nav || !toggle) {
        return;
    }

    const closeNavigation = () => {
        nav.classList.remove("is-open");
        toggle.classList.remove("is-open");

        toggle.setAttribute(
            "aria-expanded",
            "false"
        );
    };

    toggle.addEventListener("click", () => {
        const isOpen =
            nav.classList.toggle("is-open");

        toggle.classList.toggle(
            "is-open",
            isOpen
        );

        toggle.setAttribute(
            "aria-expanded",
            String(isOpen)
        );
    });

    nav
        .querySelectorAll("a")
        .forEach((link) => {
            link.addEventListener(
                "click",
                closeNavigation
            );
        });

    document.addEventListener(
        "click",
        (event) => {
            if (
                window.innerWidth <= 720 &&
                !topbar.contains(event.target)
            ) {
                closeNavigation();
            }
        }
    );

    window.addEventListener(
        "resize",
        () => {
            if (window.innerWidth > 720) {
                closeNavigation();
            }
        }
    );
});