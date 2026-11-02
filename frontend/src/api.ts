export async function getUsers() {
  const res = await fetch('/api/v1/users');
  return res.json();
}
