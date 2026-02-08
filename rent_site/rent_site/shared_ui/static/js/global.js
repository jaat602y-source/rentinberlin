function toggleNav() {
  const el = document.getElementById("navLinks");
  if (!el) return;
  el.classList.toggle("open");
}
window.toggleNav = toggleNav;

function togglePassword() {
  const pwd = document.getElementById("pwd");
  if (!pwd) return;
  pwd.type = (pwd.type === "password") ? "text" : "password";
}
window.togglePassword = togglePassword;
