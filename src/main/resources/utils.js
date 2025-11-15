// Utility functions for better UX

// Toast notification system
function showToast(message, type = "info", duration = 3000) {
  // Remove existing toast if any
  const existingToast = document.querySelector(".toast");
  if (existingToast) {
    existingToast.remove();
  }

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  // Auto remove after duration
  setTimeout(() => {
    toast.style.animation = "toastSlideUp 0.3s ease-out reverse";
    setTimeout(() => toast.remove(), 300);
  }, duration);

  // Click to dismiss
  toast.addEventListener("click", () => {
    toast.style.animation = "toastSlideUp 0.3s ease-out reverse";
    setTimeout(() => toast.remove(), 300);
  });
}

// Loading overlay
function showLoading(message = "Loading...") {
  const overlay = document.createElement("div");
  overlay.className = "loading-overlay";
  overlay.id = "loading-overlay";
  overlay.innerHTML = `
    <div class="loading-content">
      <div class="loading-spinner"></div>
      <div class="loading-text">${message}</div>
    </div>
  `;
  document.body.appendChild(overlay);
  document.body.classList.add("modal-open");
}

function hideLoading() {
  const overlay = document.getElementById("loading-overlay");
  if (overlay) {
    overlay.style.opacity = "0";
    setTimeout(() => {
      overlay.remove();
      document.body.classList.remove("modal-open");
    }, 200);
  }
}

// Debounce function for search inputs
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Throttle function for scroll events
function throttle(func, limit) {
  let inThrottle;
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

// Smooth scroll to bottom
function scrollToBottom(element, smooth = true) {
  if (!element) return;

  // Use requestAnimationFrame for better performance
  requestAnimationFrame(() => {
    const scrollOptions = {
      top: element.scrollHeight,
      behavior: smooth ? "smooth" : "auto",
    };

    element.scrollTo(scrollOptions);

    // Fallback for browsers that don't support smooth scroll
    if (!smooth || !("scrollBehavior" in document.documentElement.style)) {
      element.scrollTop = element.scrollHeight;
    }
  });
}

// Check if element is in viewport
function isInViewport(element) {
  const rect = element.getBoundingClientRect();
  return (
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <=
      (window.innerHeight || document.documentElement.clientHeight) &&
    rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
}

// Format date for display
function formatDate(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const diff = now - date;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;

  return date.toLocaleDateString();
}

// Touch gesture handler for mobile
class TouchGestureHandler {
  constructor(element, options = {}) {
    this.element = element;
    this.onSwipeLeft = options.onSwipeLeft || null;
    this.onSwipeRight = options.onSwipeRight || null;
    this.onSwipeUp = options.onSwipeUp || null;
    this.onSwipeDown = options.onSwipeDown || null;
    this.threshold = options.threshold || 50;

    this.startX = 0;
    this.startY = 0;
    this.endX = 0;
    this.endY = 0;

    this.init();
  }

  init() {
    this.element.addEventListener(
      "touchstart",
      (e) => {
        this.startX = e.touches[0].clientX;
        this.startY = e.touches[0].clientY;
      },
      { passive: true }
    );

    this.element.addEventListener(
      "touchend",
      (e) => {
        this.endX = e.changedTouches[0].clientX;
        this.endY = e.changedTouches[0].clientY;
        this.handleSwipe();
      },
      { passive: true }
    );
  }

  handleSwipe() {
    const deltaX = this.endX - this.startX;
    const deltaY = this.endY - this.startY;

    if (Math.abs(deltaX) > Math.abs(deltaY)) {
      // Horizontal swipe
      if (Math.abs(deltaX) > this.threshold) {
        if (deltaX > 0 && this.onSwipeRight) {
          this.onSwipeRight();
        } else if (deltaX < 0 && this.onSwipeLeft) {
          this.onSwipeLeft();
        }
      }
    } else {
      // Vertical swipe
      if (Math.abs(deltaY) > this.threshold) {
        if (deltaY > 0 && this.onSwipeDown) {
          this.onSwipeDown();
        } else if (deltaY < 0 && this.onSwipeUp) {
          this.onSwipeUp();
        }
      }
    }
  }
}

// Prevent zoom on double tap (mobile)
function preventDoubleTapZoom() {
  let lastTouchEnd = 0;
  document.addEventListener(
    "touchend",
    (event) => {
      const now = Date.now();
      if (now - lastTouchEnd <= 300) {
        event.preventDefault();
      }
      lastTouchEnd = now;
    },
    false
  );
}

// Initialize on page load
if (typeof document !== "undefined") {
  preventDoubleTapZoom();
}

// Export for use in other scripts
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    showToast,
    showLoading,
    hideLoading,
    debounce,
    throttle,
    scrollToBottom,
    isInViewport,
    formatDate,
    TouchGestureHandler,
  };
}
