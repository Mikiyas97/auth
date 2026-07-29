const firebaseConfig = {
  apiKey: "AIzaSyD6uplO-rXInBhbqGgoeJVd08-qjwHijjs",
  authDomain: "insalogin-e9a32.firebaseapp.com",
  projectId: "insalogin-e9a32",
  storageBucket: "insalogin-e9a32.firebasestorage.app",
  messagingSenderId: "606279562496",
  appId: "1:606279562496:web:afd19998533e851e912fe5",
  measurementId: "G-F5RY346BQX"
};

// Initialize Firebase
const app = firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const provider = new firebase.auth.GoogleAuthProvider();
