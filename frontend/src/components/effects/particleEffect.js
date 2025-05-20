// Create this file in src/components/effects/particleEffect.js

class Particle {
    constructor(x, y, size, color, speed) {
      this.x = x;
      this.y = y;
      this.size = size;
      this.color = color;
      this.speed = speed;
      this.angle = Math.random() * 2 * Math.PI;
      this.element = null;
      this.create();
    }
    
    create() {
      const particle = document.createElement('div');
      particle.className = 'particle';
      particle.style.width = `${this.size}px`;
      particle.style.height = `${this.size}px`;
      particle.style.backgroundColor = this.color;
      particle.style.left = `${this.x}px`;
      particle.style.top = `${this.y}px`;
      particle.style.opacity = Math.random() * 0.5 + 0.3;
      document.body.appendChild(particle);
      this.element = particle;
    }
    
    update() {
      // Update position
      this.x += Math.cos(this.angle) * this.speed;
      this.y += Math.sin(this.angle) * this.speed;
      
      // Slightly change angle for organic movement
      this.angle += (Math.random() - 0.5) * 0.05;
      
      // Check boundaries and reverse if needed
      if (this.x <= 0 || this.x >= window.innerWidth) {
        this.angle = Math.PI - this.angle;
      }
      if (this.y <= 0 || this.y >= window.innerHeight) {
        this.angle = -this.angle;
      }
      
      // Update DOM element
      this.element.style.left = `${this.x}px`;
      this.element.style.top = `${this.y}px`;
    }
  }
  
  export function initParticles() {
    // Clean up any existing particles first
    const existingParticles = document.querySelectorAll('.particle');
    existingParticles.forEach(p => p.remove());
    
    // Create particles based on screen size
    const particleCount = Math.min(window.innerWidth, window.innerHeight) / 10;
    const particles = [];
    
    for (let i = 0; i < particleCount; i++) {
      const x = Math.random() * window.innerWidth;
      const y = Math.random() * window.innerHeight;
      const size = Math.random() * 2 + 1;
      const colors = [
        'rgba(255, 255, 255, 0.5)',
        'rgba(0, 212, 255, 0.4)',
        'rgba(5, 217, 232, 0.4)'
      ];
      const color = colors[Math.floor(Math.random() * colors.length)];
      const speed = Math.random() * 0.5 + 0.1;
      
      particles.push(new Particle(x, y, size, color, speed));
    }
    
    function animate() {
      particles.forEach(particle => particle.update());
      requestAnimationFrame(animate);
    }
    
    animate();
    
    // Handle window resize
    window.addEventListener('resize', () => {
      // Remove existing particles
      particles.forEach(p => p.element.remove());
      particles.length = 0;
      
      // Reinitialize
      initParticles();
    });
  }