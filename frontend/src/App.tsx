import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Shell } from '@/components/layout/Shell';
import { Home } from '@/pages/Home';
import { Scan } from '@/pages/Scan';
import { Results } from '@/pages/Results';
import { Export } from '@/pages/Export';
import { Catalog } from '@/pages/Catalog';
import { NotFound } from '@/pages/NotFound';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<Home />} />
            <Route path="scan" element={<Scan />} />
            <Route path="results/:scanId" element={<Results />} />
            <Route path="export/:scanId" element={<Export />} />
            <Route path="catalog" element={<Catalog />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
