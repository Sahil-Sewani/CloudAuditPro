#!/bin/bash
# CloudAuditPro Startup Script

# Move to the backend directory and start FastAPI
echo "🚀 Starting backend (FastAPI)..."
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload &
BACKEND_PID=$!

# Move to the frontend directory and start React app
echo "🌐 Starting frontend (Vite)..."
cd ../frontend
npm run dev &

FRONTEND_PID=$!

# Wait for user to press Ctrl+C to stop everything
echo "✅ CloudAuditPro is running!"
echo "   → Backend:  http://127.0.0.1:8000"
echo "   → Frontend: http://localhost:5173"
echo
echo "Press Ctrl+C to stop both servers."

# Trap Ctrl+C (SIGINT) to cleanly stop both processes
trap "echo '🛑 Stopping servers...'; kill $BACKEND_PID $FRONTEND_PID; exit 0" INT

# Keep script running
wait
