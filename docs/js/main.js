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
        
        // Comments first (to avoid highlighting # in strings)
        html = html.replace(/(#.*$)/gm, '<span class="comment">$1</span>');
        
        // Strings (do this before keywords to avoid highlighting keywords in strings)
        html = html.replace(/"([^"]*)"/g, '<span class="string">"$1"</span>');
        html = html.replace(/'([^']*)'/g, '<span class="string">\'$1\'</span>');
        
        // Functions (match function names including underscores)
        html = html.replace(/([a-zA-Z_]\w*)\s*\(/g, '<span class="function">$1</span>(');
        
        // Keywords (do this after functions to avoid conflicts)
        const keywords = ['import', 'from', 'if', 'else', 'elif', 'def', 'class', 'return', 'for', 'while', 'in', 'or', 'and', 'not', 'True', 'False', 'None', 'print'];
        keywords.forEach(keyword => {
            // Simple word boundary check
            const regex = new RegExp(`\\b${keyword}\\b`, 'g');
            html = html.replace(regex, (match, offset, string) => {
                // Check if we're inside a tag or already highlighted
                const before = string.substring(Math.max(0, offset - 20), offset);
                const after = string.substring(offset, offset + 20);
                if (before.includes('<span') || before.includes('class=') || after.includes('</span>')) {
                    return match;
                }
                return `<span class="keyword">${match}</span>`;
            });
        });
        
        block.innerHTML = html;
    });
    
    // ================================
    // YAML Syntax Highlighting
    // ================================
    const yamlBlocks = document.querySelectorAll('code.language-yaml');
    
    yamlBlocks.forEach(block => {
        let html = block.innerHTML;
        
        // Comments
        html = html.replace(/(#.*$)/gm, '<span class="comment">$1</span>');
        
        // Keys (before colon)
        html = html.replace(/^(\s*)([a-zA-Z_-]+):/gm, '$1<span class="keyword">$2</span>:');
        
        // Strings in quotes
        html = html.replace(/"([^"]*)"/g, '<span class="string">"$1"</span>');
        html = html.replace(/'([^']*)'/g, '<span class="string">\'$1\'</span>');
        
        // List items
        html = html.replace(/^(\s*)-\s+/gm, '$1<span class="keyword">-</span> ');
        
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