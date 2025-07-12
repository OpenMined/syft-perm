// SyftPerm Documentation JavaScript
// Basic functionality for navigation and mobile support

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Highlight active section in sidebar
    function updateActiveSidebarLink() {
        const sections = document.querySelectorAll('[id]');
        const sidebarLinks = document.querySelectorAll('.doc-sidebar a[href^="#"]');
        
        let currentSection = '';
        sections.forEach(section => {
            const rect = section.getBoundingClientRect();
            if (rect.top <= 100 && rect.bottom >= 100) {
                currentSection = section.id;
            }
        });

        sidebarLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + currentSection) {
                link.classList.add('active');
            }
        });
    }

    // Update active sidebar link on scroll
    if (document.querySelector('.doc-sidebar')) {
        window.addEventListener('scroll', updateActiveSidebarLink);
        updateActiveSidebarLink(); // Initial call
    }

    // Copy code block functionality
    function addCopyButtons() {
        const codeBlocks = document.querySelectorAll('.code-block');
        
        codeBlocks.forEach(block => {
            // Skip if already has copy button
            if (block.querySelector('.copy-button')) return;
            
            const button = document.createElement('button');
            button.className = 'copy-button';
            button.innerHTML = '📋 Copy';
            button.style.cssText = `
                position: absolute;
                top: 8px;
                right: 8px;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: white;
                padding: 4px 8px;
                font-size: 12px;
                border-radius: 3px;
                cursor: pointer;
                transition: background 0.2s;
            `;
            
            button.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(block.textContent);
                    button.innerHTML = '✅ Copied!';
                    setTimeout(() => {
                        button.innerHTML = '📋 Copy';
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy:', err);
                    button.innerHTML = '❌ Failed';
                    setTimeout(() => {
                        button.innerHTML = '📋 Copy';
                    }, 2000);
                }
            });
            
            button.addEventListener('mouseenter', () => {
                button.style.background = 'rgba(255, 255, 255, 0.2)';
            });
            
            button.addEventListener('mouseleave', () => {
                button.style.background = 'rgba(255, 255, 255, 0.1)';
            });
            
            // Make code block container relative for absolute positioning
            block.style.position = 'relative';
            block.appendChild(button);
        });
    }

    // Add copy buttons to code blocks
    addCopyButtons();

    // Mobile navigation toggle (if we add a mobile menu later)
    const mobileMenuButton = document.querySelector('.mobile-menu-button');
    const mobileMenu = document.querySelector('.mobile-menu');
    
    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', () => {
            mobileMenu.classList.toggle('open');
            mobileMenuButton.classList.toggle('open');
        });
    }

    // Close mobile menu when clicking outside
    document.addEventListener('click', (e) => {
        if (mobileMenu && !mobileMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
            mobileMenu.classList.remove('open');
            mobileMenuButton.classList.remove('open');
        }
    });

    // Search functionality (basic implementation)
    const searchInput = document.querySelector('.search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            const searchableElements = document.querySelectorAll('h1, h2, h3, h4, p, .api-method-name');
            
            searchableElements.forEach(element => {
                const text = element.textContent.toLowerCase();
                const parent = element.closest('.card, .api-method, section');
                
                if (query && !text.includes(query)) {
                    if (parent) parent.style.display = 'none';
                } else {
                    if (parent) parent.style.display = '';
                }
            });
        });
    }

    // Table of contents generation for long pages
    function generateTableOfContents() {
        const tocContainer = document.querySelector('.table-of-contents');
        if (!tocContainer) return;

        const headings = document.querySelectorAll('h2, h3, h4');
        if (headings.length === 0) return;

        const tocList = document.createElement('ul');
        tocList.className = 'toc-list';

        headings.forEach(heading => {
            if (!heading.id) {
                // Generate ID from heading text
                heading.id = heading.textContent.toLowerCase()
                    .replace(/[^\w\s-]/g, '')
                    .replace(/\s+/g, '-');
            }

            const li = document.createElement('li');
            li.className = `toc-${heading.tagName.toLowerCase()}`;
            
            const link = document.createElement('a');
            link.href = '#' + heading.id;
            link.textContent = heading.textContent;
            
            li.appendChild(link);
            tocList.appendChild(li);
        });

        tocContainer.appendChild(tocList);
    }

    generateTableOfContents();

    // Print-friendly styles
    window.addEventListener('beforeprint', () => {
        document.body.classList.add('printing');
    });

    window.addEventListener('afterprint', () => {
        document.body.classList.remove('printing');
    });

    // Analytics or tracking (placeholder)
    function trackPageView() {
        // Add analytics tracking here if needed
        // Example: gtag('event', 'page_view', { page_title: document.title });
    }

    trackPageView();
});

// Utility functions
window.SyftPermDocs = {
    // Function to highlight search terms
    highlightSearchTerms: function(query) {
        const regex = new RegExp(`(${query})`, 'gi');
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );

        const textNodes = [];
        let node;
        while (node = walker.nextNode()) {
            if (node.nodeValue.toLowerCase().includes(query.toLowerCase())) {
                textNodes.push(node);
            }
        }

        textNodes.forEach(textNode => {
            const parent = textNode.parentNode;
            const wrapper = document.createElement('span');
            wrapper.innerHTML = textNode.nodeValue.replace(regex, '<mark>$1</mark>');
            parent.replaceChild(wrapper, textNode);
        });
    },

    // Function to clear search highlights
    clearHighlights: function() {
        const highlights = document.querySelectorAll('mark');
        highlights.forEach(mark => {
            mark.outerHTML = mark.innerHTML;
        });
    },

    // Function to scroll to element with offset for fixed header
    scrollToElement: function(element) {
        const headerHeight = document.querySelector('.header').offsetHeight;
        const elementPosition = element.offsetTop - headerHeight - 20;
        
        window.scrollTo({
            top: elementPosition,
            behavior: 'smooth'
        });
    }
};

// Expose utility functions globally
window.scrollToElement = window.SyftPermDocs.scrollToElement;