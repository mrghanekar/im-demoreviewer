import { useEffect, useState, useRef } from 'react';

const GOOGLE_WITTY_LINES = [
  "I'm Feeling Lucky...",
  "Re-routing encryption...",
  "De-duplicating the internet...",
  "Indexing 42 billion pages...",
  "Did you mean: recursion?",
  "Deploying more containers...",
  "Warming up the data center...",
  "Checking robots.txt...",
  "Querying the Knowledge Graph...",
  "Spawning borg jobs...",
  "Optimizing MapReduce...",
  "Calculating PageRank...",
  "Waiting for DNS propagation...",
  "Spinning up BigTable...",
  "Locating cached cats...",
  "Defining 'Don't be evil'...",
  "Compiling Protocol Buffers...",
  "Searching for the algorithm...",
  "Checking quota limits...",
  "Generating Doodles...",
  "Asking the Oracle...",
  "Allocating Tensor Processing Units...",
  "Hydrating the cache...",
  "Synthesizing search results...",
  "Performing quantum supremacy...",
  // Tech Dad Jokes & Geek Humor
  "There are 10 types of people: those who know binary, and those who don't.",
  "A SQL query walks into a bar... 'Can I join you?'",
  "Why do Java developers wear glasses? Because they don't C#.",
  "Knock, knock. Race condition. Who's there?",
  "Downloading more RAM...",
  "Exiting vim... eventually...",
  "I would tell you a UDP joke, but you might not get it.",
  "Checking if you are a robot...",
  "Refactoring spaghetti code...",
  "Consulting Stack Overflow...",
  "Turning it off and on again...",
  "Training the neural net to laugh...",
  "Waiting for the Singularity...",
  "Replacing null with undefined...",
  "Asking Gemini for a raise...",
  "Deleting production... just kidding.",
  "Searching for the 'Any' key...",
  "Resolving git conflicts...",
  "Compiling... 99% complete...",
  "Detecting human presence...",
  "Initiating self-destruct sequence... cancelled.",
  "Why did the edge server go broke? It lost its cache.",
  "Debugging with print statements...",
  "Proving P=NP...",
  "Simulating free will...",
  "Calibrating flux capacitors...",
  "Pretending to be busy...",
  "Writing documentation... (lol)",
  "Blaming the firewall...",
  "It works on my machine!"
];

interface GlimmerLine {
  id: number;
  text: string;
  x: number;
  y: number;
  duration: number;
  color: string;
  textShadow: string;
}

export function GlimmeringBackground() {
  const [lines, setLines] = useState<GlimmerLine[]>([]);
  const countRef = useRef(0);

  useEffect(() => {
    const interval = setInterval(() => {
      const id = countRef.current++;
      const text = GOOGLE_WITTY_LINES[Math.floor(Math.random() * GOOGLE_WITTY_LINES.length)];
      
      // Restrict to side margins to avoid overlapping main content
      // Left side: 2% to 15%
      // Right side: 85% to 98%
      const side = Math.random() > 0.5 ? 'left' : 'right';
      const x = side === 'left' 
        ? 2 + Math.random() * 13 
        : 85 + Math.random() * 13;
      
      const y = 10 + Math.random() * 80;
      const duration = 4000 + Math.random() * 4000; // Slower animation
      
      const isGreen = Math.random() > 0.8;
      const color = isGreen ? '#00ff41' : '#8b949e';
      const textShadow = isGreen ? '0 0 5px rgba(0, 255, 65, 0.5)' : 'none';

      const newLine: GlimmerLine = { id, text, x, y, duration, color, textShadow };
      
      setLines(prev => [...prev, newLine]);

      // Cleanup
      setTimeout(() => {
        setLines(prev => prev.filter(l => l.id !== id));
      }, duration);

    }, 4000); // Add new line every 4 seconds (half frequency)

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none overflow-hidden z-0 select-none">
      {lines.map(line => (
        <div
          key={line.id}
          className="absolute text-[--color-text-muted] opacity-0 animate-glimmer font-mono text-xs whitespace-nowrap"
          style={{
            left: `${line.x}%`,
            top: `${line.y}%`,
            animationDuration: `${line.duration}ms`,
            color: line.color,
            textShadow: line.textShadow
          }}
        >
          {line.text}
        </div>
      ))}
      <style>{`
        @keyframes glimmer {
          0% { opacity: 0; transform: translateY(10px) scale(0.9); }
          20% { opacity: 0.3; transform: translateY(0) scale(1); }
          80% { opacity: 0.3; transform: translateY(0) scale(1); }
          100% { opacity: 0; transform: translateY(-10px) scale(0.9); }
        }
        .animate-glimmer {
          animation-name: glimmer;
          animation-timing-function: ease-in-out;
          animation-fill-mode: forwards;
        }
      `}</style>
    </div>
  );
}
