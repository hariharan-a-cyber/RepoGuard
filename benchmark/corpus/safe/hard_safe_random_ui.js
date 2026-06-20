function pickConfetti() {
  // SAFE: Math.random for a non-security cosmetic effect (color choice)
  const colors = ["red", "green", "blue"];
  return colors[Math.floor(Math.random() * colors.length)];
}
