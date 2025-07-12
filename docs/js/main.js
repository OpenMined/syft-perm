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
        // Get the text content first to avoid HTML entity issues
        let text = block.textContent || '';
        
        // Escape HTML special characters
        text = text.replace(/&/g, '&amp;')
                   .replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;');
        
        // Apply syntax highlighting
        // Comments first (to avoid highlighting # in strings)
        text = text.replace(/(#.*$)/gm, '<span class="comment">$1</span>');
        
        // Strings (do this before keywords to avoid highlighting keywords in strings)
        text = text.replace(/"([^"]*)"/g, '<span class="string">"$1"</span>');
        text = text.replace(/'([^']*)'/g, '<span class="string">\'$1\'</span>');
        
        // Functions (match function names including underscores)
        text = text.replace(/([a-zA-Z_]\w*)\s*\(/g, '<span class="function">$1</span>(');
        
        // Keywords (do this after functions to avoid conflicts)
        const keywords = ['import', 'from', 'if', 'else', 'elif', 'def', 'class', 'return', 'for', 'while', 'in', 'or', 'and', 'not', 'True', 'False', 'None', 'print'];
        keywords.forEach(keyword => {
            const regex = new RegExp(`\\b${keyword}\\b(?![^<]*>)`, 'g');
            text = text.replace(regex, `<span class="keyword">${keyword}</span>`);
        });
        
        // Set the HTML with highlighting
        block.innerHTML = text;
    });
    
    // ================================
    // YAML Syntax Highlighting
    // ================================
    const yamlBlocks = document.querySelectorAll('code.language-yaml');
    
    yamlBlocks.forEach(block => {
        // Get the text content to ensure we're working with plain text
        let text = block.textContent || '';
        
        // Escape HTML special characters
        text = text.replace(/&/g, '&amp;')
                   .replace(/</g, '&lt;')
                   .replace(/>/g, '&gt;');
        
        // Apply YAML syntax highlighting
        // Comments (must be done first)
        text = text.replace(/(#.*$)/gm, '<span class="comment">$1</span>');
        
        // Strings in quotes
        text = text.replace(/'([^']*)'/g, '<span class="string">\'$1\'</span>');
        text = text.replace(/"([^"]*)"/g, '<span class="string">"$1"</span>');
        
        // Keys (before colon) - make sure not to match inside strings
        text = text.replace(/^(\s*)([a-zA-Z_-]+)(?=:)/gm, '$1<span class="keyword">$2</span>');
        
        // List items
        text = text.replace(/^(\s*)(-)(\s+)/gm, '$1<span class="keyword">$2</span>$3');
        
        // Set the final HTML
        block.innerHTML = text;
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