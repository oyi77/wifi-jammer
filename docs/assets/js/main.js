// WiFi Jammer GitHub Pages - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initMobileMenu();
    initCodeCopy();
    initTabs();
    initExpandables();
    initScrollToTop();
    initSmoothScroll();
});

// Mobile Menu Toggle
function initMobileMenu() {
    const toggle = document.querySelector('.mobile-menu-toggle');
    const navLinks = document.querySelector('.nav-links');
    
    if (toggle && navLinks) {
        toggle.addEventListener('click', function() {
            navLinks.classList.toggle('active');
        });
        
        // Close menu when clicking outside
        document.addEventListener('click', function(event) {
            if (!toggle.contains(event.target) && !navLinks.contains(event.target)) {
                navLinks.classList.remove('active');
            }
        });
    }
}

// Code Copy to Clipboard
function initCodeCopy() {
    const codeBlocks = document.querySelectorAll('pre code');
    
    codeBlocks.forEach(function(codeBlock) {
        const pre = codeBlock.parentElement;
        if (pre.tagName === 'PRE') {
            const button = document.createElement('button');
            button.className = 'copy-btn';
            button.textContent = 'Copy';
            button.setAttribute('aria-label', 'Copy code to clipboard');
            pre.style.position = 'relative';
            pre.appendChild(button);
            
            button.addEventListener('click', function() {
                const text = codeBlock.textContent;
                navigator.clipboard.writeText(text).then(function() {
                    button.textContent = 'Copied!';
                    button.classList.add('copied');
                    
                    setTimeout(function() {
                        button.textContent = 'Copy';
                        button.classList.remove('copied');
                    }, 2000);
                }).catch(function(err) {
                    console.error('Failed to copy text: ', err);
                    button.textContent = 'Error';
                    setTimeout(function() {
                        button.textContent = 'Copy';
                    }, 2000);
                });
            });
        }
    });
}

// Tab Switching
function initTabs() {
    const tabContainers = document.querySelectorAll('.tab-container');
    
    tabContainers.forEach(function(container) {
        const buttons = container.querySelectorAll('.tab-button');
        const contents = container.querySelectorAll('.tab-content');
        
        buttons.forEach(function(button, index) {
            button.addEventListener('click', function() {
                // Remove active class from all buttons and contents
                buttons.forEach(function(btn) {
                    btn.classList.remove('active');
                });
                contents.forEach(function(content) {
                    content.classList.remove('active');
                });
                
                // Add active class to clicked button and corresponding content
                button.classList.add('active');
                if (contents[index]) {
                    contents[index].classList.add('active');
                }
            });
        });
        
        // Activate first tab by default
        if (buttons.length > 0 && contents.length > 0) {
            buttons[0].classList.add('active');
            contents[0].classList.add('active');
        }
    });
}

// Expandable Sections
function initExpandables() {
    const expandables = document.querySelectorAll('.expandable');
    
    expandables.forEach(function(expandable) {
        const header = expandable.querySelector('.expandable-header');
        const content = expandable.querySelector('.expandable-content');
        
        if (header && content) {
            header.addEventListener('click', function() {
                expandable.classList.toggle('expanded');
                content.classList.toggle('expanded');
            });
        }
    });
}

// Scroll to Top Button
function initScrollToTop() {
    const button = document.querySelector('.scroll-to-top');
    
    if (button) {
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                button.classList.add('visible');
            } else {
                button.classList.remove('visible');
            }
        });
        
        button.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
}

// Smooth Scroll for Anchor Links
function initSmoothScroll() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(function(link) {
        link.addEventListener('click', function(e) {
            const href = link.getAttribute('href');
            if (href !== '#' && href.length > 1) {
                const target = document.querySelector(href);
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                    
                    // Update URL without jumping
                    history.pushState(null, null, href);
                }
            }
        });
    });
}

// Highlight current page in navigation
function highlightCurrentPage() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(function(link) {
        const linkPath = new URL(link.href).pathname;
        if (linkPath === currentPath || 
            (currentPath === '/' && linkPath.includes('index.html'))) {
            link.style.color = 'var(--accent-cyan)';
            link.style.fontWeight = 'bold';
        }
    });
}

// Call on page load
highlightCurrentPage();

