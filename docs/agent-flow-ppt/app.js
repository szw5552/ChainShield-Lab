const slides = Array.from(document.querySelectorAll("[data-slide]"));
const dots = Array.from(document.querySelectorAll("[data-goto]"));
const currentLabel = document.querySelector("[data-current]");
const prevButton = document.querySelector('[data-action="prev"]');
const nextButton = document.querySelector('[data-action="next"]');

let activeIndex = 0;

document.body.classList.add("is-enhanced");

function formatIndex(index) {
  return String(index + 1).padStart(2, "0");
}

function showSlide(index) {
  activeIndex = Math.max(0, Math.min(index, slides.length - 1));

  slides.forEach((slide, slideIndex) => {
    const isActive = slideIndex === activeIndex;
    slide.classList.toggle("is-active", isActive);
    slide.setAttribute("aria-hidden", String(!isActive));
  });

  dots.forEach((dot, dotIndex) => {
    dot.classList.toggle("is-active", dotIndex === activeIndex);
  });

  if (currentLabel) {
    currentLabel.textContent = formatIndex(activeIndex);
  }
}

prevButton?.addEventListener("click", () => showSlide(activeIndex - 1));
nextButton?.addEventListener("click", () => showSlide(activeIndex + 1));

dots.forEach((dot) => {
  dot.addEventListener("click", () => showSlide(Number(dot.dataset.goto || 0)));
});

window.addEventListener("keydown", (event) => {
  if (event.key === "ArrowRight" || event.key === " ") {
    event.preventDefault();
    showSlide(activeIndex + 1);
  }
  if (event.key === "ArrowLeft") {
    event.preventDefault();
    showSlide(activeIndex - 1);
  }
});

showSlide(0);

const canvas = document.getElementById("motion-canvas");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (canvas instanceof HTMLCanvasElement && !reducedMotion) {
  const ctx = canvas.getContext("2d");
  const packets = [];
  const colors = ["#00a7a7", "#3478f6", "#ffd447", "#ff6f61", "#8fd14f"];

  function resize() {
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.floor(window.innerWidth * ratio);
    canvas.height = Math.floor(window.innerHeight * ratio);
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    ctx?.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function seedPackets() {
    packets.length = 0;
    const count = Math.max(18, Math.floor(window.innerWidth / 72));
    for (let index = 0; index < count; index += 1) {
      packets.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        size: 4 + Math.random() * 7,
        speed: 0.35 + Math.random() * 0.9,
        color: colors[index % colors.length],
        phase: Math.random() * Math.PI * 2,
      });
    }
  }

  function draw() {
    if (!ctx) return;
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    ctx.globalAlpha = 0.22;

    packets.forEach((packet) => {
      packet.x += packet.speed;
      packet.y += Math.sin(Date.now() / 900 + packet.phase) * 0.18;
      if (packet.x > window.innerWidth + 20) {
        packet.x = -20;
        packet.y = Math.random() * window.innerHeight;
      }
      ctx.beginPath();
      if (typeof ctx.roundRect === "function") {
        ctx.roundRect(packet.x, packet.y, packet.size * 3.2, packet.size, 3);
      } else {
        ctx.rect(packet.x, packet.y, packet.size * 3.2, packet.size);
      }
      ctx.fillStyle = packet.color;
      ctx.fill();
    });

    ctx.globalAlpha = 1;
    requestAnimationFrame(draw);
  }

  window.addEventListener("resize", () => {
    resize();
    seedPackets();
  });

  resize();
  seedPackets();
  requestAnimationFrame(draw);
}
