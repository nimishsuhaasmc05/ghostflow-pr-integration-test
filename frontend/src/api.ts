export async function getUsers() {
  const res = await fetch('/api/v1/users');
  return res.json();
}

export async function getHealth() {
  const res = await fetch('/api/v1/health');
  return res.json();
}
