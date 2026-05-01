document.addEventListener("DOMContentLoaded", () => {
    const body = document.body;
    const toggle = document.getElementById("themeToggle");
    const icon = document.getElementById("themeIcon");
    const loader = document.getElementById("scanLoader");
    const form = document.getElementById("scanForm");
    const scanButton = document.getElementById("scanBtn");
    const scanInput = document.getElementById("url");
    const formErrorPanel = document.getElementById("formErrorPanel");
    const formErrorText = document.getElementById("formErrorText");
    const shareButton = document.getElementById("shareButton");
    const shareMenu = document.getElementById("shareMenu");
    const shareOptions = document.querySelectorAll("[data-share-target]");
    const shareToast = document.getElementById("shareToast");
    const reportShareToast = document.getElementById("reportShareToast");
    const reportShareModal = document.getElementById("shareReportModal");
    const reportShareOptions = document.querySelectorAll("[data-share-modal]");
    const storageKey = "webguard-theme";

    const applyTheme = (theme) => {
        body.classList.remove("dark-mode", "light-mode");
        body.classList.add(theme);

        if (icon) {
            icon.classList.remove("fa-moon", "fa-sun");
            icon.classList.add(theme === "dark-mode" ? "fa-sun" : "fa-moon");
        }
    };

    const savedTheme = localStorage.getItem(storageKey) || "dark-mode";
    applyTheme(savedTheme);

    const resultContainer = document.querySelector(".result-container");
    if (resultContainer) {
        requestAnimationFrame(() => {
            resultContainer.classList.add("show");
        });
    }

    const gradeElement = document.querySelector(".grade-badge");
    if (gradeElement) {
        const grade = gradeElement.innerText.trim();
        if (grade) {
            gradeElement.classList.add(`grade-${grade}`);
            gradeElement.closest(".stat-card")?.classList.add(`grade-${grade}`);
            document.querySelector(".score-value")?.classList.add(`score-${grade}`);

            const verdictEl = document.querySelector(".security-verdict");
            const verdictMap = {
                A: "Strong security — well configured",
                B: "Good security — minor improvements possible",
                C: "Moderate risk — improvements recommended",
                D: "Weak security — action required",
                E: "High risk — immediate fixes needed"
            };

            if (verdictEl) {
                verdictEl.textContent = verdictMap[grade] || "Security posture available";
                verdictEl.classList.add(`verdict-${grade}`);
            }

            const analysisTypeEl = document.querySelector(".analysis-type");
            if (analysisTypeEl) {
                const sectionTitles = Array.from(document.querySelectorAll(".section-title"))
                    .map((element) => element.textContent.trim());
                const hasTlsSignals = sectionTitles.includes("TLS / HTTPS Info");
                const hasCookieSignals = sectionTitles.includes("Cookie Security Issues");

                analysisTypeEl.innerHTML = (hasTlsSignals || hasCookieSignals)
                    ? '<i class="fa-solid fa-layer-group me-1"></i>Headers + Cookies + TLS'
                    : '<i class="fa-solid fa-layer-group me-1"></i>Headers Only';
            }
        }
    }

    if (toggle) {
        toggle.addEventListener("click", () => {
            const nextTheme = body.classList.contains("dark-mode") ? "light-mode" : "dark-mode";
            localStorage.setItem(storageKey, nextTheme);
            applyTheme(nextTheme);
        });
    }

    if (form && loader) {
        form.addEventListener("submit", (event) => {
            const urlValue = scanInput?.value?.trim() || "";
            if (!urlValue) {
                event.preventDefault();
                if (formErrorText) {
                    formErrorText.textContent = "Enter a valid URL";
                }
                formErrorPanel?.classList.remove("d-none");
                scanInput?.focus();
                return;
            }

            console.log("Form data:", new FormData(form).get("url"));
            formErrorPanel?.classList.add("d-none");
            loader.classList.add("active");
            scanButton?.classList.add("is-loading");
            if (scanButton) {
                scanButton.disabled = true;
            }
        });
    }

    if (shareButton) {
        const setShareMenuState = (isOpen) => {
            if (!shareMenu) {
                return;
            }

            shareMenu.classList.toggle("active", isOpen);
            shareMenu.setAttribute("aria-hidden", String(!isOpen));
            shareButton.setAttribute("aria-expanded", String(isOpen));
        };

        const showShareToast = () => {
            if (shareToast && window.bootstrap?.Toast) {
                const toast = bootstrap.Toast.getOrCreateInstance(shareToast, {
                    delay: 1800
                });
                toast.show();
            }
        };

        const fallbackCopy = () => {
            const tempInput = document.createElement("input");
            tempInput.value = window.location.href;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand("copy");
            document.body.removeChild(tempInput);
            showShareToast();
        };

        shareButton.addEventListener("click", () => {
            const isOpen = shareMenu?.classList.contains("active");
            setShareMenuState(!isOpen);
        });

        shareOptions.forEach((option) => {
            option.addEventListener("click", async (event) => {
                const encodedUrl = encodeURIComponent(window.location.href);
                const target = option.getAttribute("data-share-target");

                if (target === "copy") {
                    event.preventDefault();

                    try {
                        if (navigator.clipboard?.writeText) {
                            await navigator.clipboard.writeText(window.location.href);
                            showShareToast();
                        } else {
                            fallbackCopy();
                        }
                    } catch (_error) {
                        fallbackCopy();
                    }

                    setShareMenuState(false);
                    return;
                }

                const shareUrls = {
                    whatsapp: `https://wa.me/?text=${encodedUrl}`,
                    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`,
                    twitter: `https://twitter.com/intent/tweet?url=${encodedUrl}`
                };

                const shareUrl = shareUrls[target];
                if (shareUrl) {
                    option.setAttribute("href", shareUrl);
                    option.setAttribute("target", "_blank");
                    option.setAttribute("rel", "noopener noreferrer");
                }

                setShareMenuState(false);
            });
        });

        document.addEventListener("click", (event) => {
            if (!shareMenu || !shareButton) {
                return;
            }

            if (!shareMenu.contains(event.target) && !shareButton.contains(event.target)) {
                setShareMenuState(false);
            }
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                setShareMenuState(false);
            }
        });
    }

    if (reportShareOptions.length) {
        const showReportToast = () => {
            const toastElement = reportShareToast;
            if (toastElement && window.bootstrap?.Toast) {
                const toast = bootstrap.Toast.getOrCreateInstance(toastElement, {
                    delay: 1800
                });
                toast.show();
            }
        };

        const fallbackCopyReportLink = (url) => {
            const tempInput = document.createElement("input");
            tempInput.value = url;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand("copy");
            document.body.removeChild(tempInput);
            showReportToast();
        };

        reportShareOptions.forEach((option) => {
            option.addEventListener("click", async (event) => {
                const target = option.getAttribute("data-share-modal");
                const shareUrl = option.getAttribute("data-share-url") || window.location.href;
                const shareText = option.getAttribute("data-share-text") || "";
                const encodedUrl = encodeURIComponent(shareUrl);
                const encodedText = encodeURIComponent(shareText);

                if (target === "copy") {
                    event.preventDefault();

                    try {
                        if (navigator.clipboard?.writeText) {
                            await navigator.clipboard.writeText(shareUrl);
                            showReportToast();
                        } else {
                            fallbackCopyReportLink(shareUrl);
                        }
                    } catch (_error) {
                        fallbackCopyReportLink(shareUrl);
                    }

                    if (reportShareModal && window.bootstrap?.Modal) {
                        bootstrap.Modal.getOrCreateInstance(reportShareModal).hide();
                    }
                    return;
                }

                const shareLinks = {
                    whatsapp: `https://wa.me/?text=${encodedText}%20${encodedUrl}`,
                    twitter: `https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}`
                };

                const destination = shareLinks[target];
                if (destination) {
                    option.setAttribute("href", destination);
                }
            });
        });
    }
});
