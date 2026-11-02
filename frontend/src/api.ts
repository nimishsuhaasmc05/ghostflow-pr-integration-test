export async function getUsers() {
  const res = await fetch('/api/v1/users');
  return res.json();
}

// Intentional API Contract Defect: /api/v1/orders/checkout does not exist on backend
export async function checkoutOrder(orderData: any) {
  const res = await fetch('/api/v1/orders/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(orderData),
  });
  return res.json();
}
