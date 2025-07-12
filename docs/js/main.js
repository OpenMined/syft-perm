// ================================
// Copy to Clipboard Functionality
// ================================
document.addEventListener('DOMContentLoaded', function() {
    // Add copy functionality to all copy buttons
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const textToCopy = this.getAttribute('data-copy');
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                
                // Show success state
                this.classList.add('copied');
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                
                // Reset after 2 seconds
                setTimeout(() => {
                    this.classList.remove('copied');
                    this.textContent = originalText;
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
    });
    
    // ================================
    // Basic Syntax Highlighting
    // ================================
    const codeBlocks = document.querySelectorAll('code.language-python');
    
    codeBlocks.forEach(block => {
        let html = block.innerHTML;
        
        // Keywords
        const keywords = ['import', 'from', 'if', 'else', 'elif', 'def', 'class', 'return', 'for', 'while', 'in', 'or', 'and', 'not', 'True', 'False', 'None'];
        keywords.forEach(keyword => {
            const regex = new RegExp(`\\b${keyword}\\b`, 'g');
            html = html.replace(regex, `<span class="keyword">${keyword}</span>`);
        });
        
        // Strings (simple version)
        html = html.replace(/"([^"]*)"/g, '<span class="string">"$1"</span>');
        html = html.replace(/'([^']*)'/g, '<span class="string">\'$1\'</span>');
        
        // Comments
        html = html.replace(/(#.*$)/gm, '<span class="comment">$1</span>');
        
        // Functions (simple version)
        html = html.replace(/(\w+)\(/g, '<span class="function">$1</span>(');
        
        block.innerHTML = html;
    });
    
    // ================================
    // Smooth Scroll for Anchor Links
    // ================================
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
    
    // ================================
    // Add Active State to Current Page
    // ================================
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath || 
            (currentPath.endsWith('/') && link.getAttribute('href') === 'index.html')) {
            link.classList.add('active');
        }
    });
});

// ================================
// Mobile Menu Toggle (if needed)
// ================================
function toggleMobileMenu() {
    const navLinks = document.querySelector('.nav-links');
    navLinks.classList.toggle('mobile-active');
}