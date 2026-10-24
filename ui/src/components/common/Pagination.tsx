import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from './Button';

interface PaginationProps {
  totalCount: number;
  limit: number;
  offset: number;
  onPageChange: (newOffset: number) => void;
  onLimitChange?: (newLimit: number) => void;
  pageSizeOptions?: number[];
  isLoading?: boolean;
}

export const Pagination: React.FC<PaginationProps> = ({
  totalCount,
  limit,
  offset,
  onPageChange,
  onLimitChange,
  pageSizeOptions = [10, 25, 50, 100],
  isLoading = false,
}) => {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(totalCount / limit));
  const startItem = totalCount === 0 ? 0 : offset + 1;
  const endItem = Math.min(offset + limit, totalCount);

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 py-3 text-xs text-slate-400 select-none">
      <div className="flex items-center gap-3">
        <span>
          Showing <span className="font-semibold text-slate-200">{startItem}</span> to{' '}
          <span className="font-semibold text-slate-200">{endItem}</span> of{' '}
          <span className="font-semibold text-slate-200">{totalCount.toLocaleString()}</span> entries
        </span>

        {onLimitChange && (
          <div className="flex items-center gap-1.5 ml-2 border-l border-slate-800 pl-4">
            <span>Per page:</span>
            <select
              value={limit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              disabled={isLoading}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              aria-label="Items per page"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        <Button
          size="sm"
          variant="secondary"
          onClick={() => onPageChange(Math.max(0, offset - limit))}
          disabled={currentPage <= 1 || isLoading}
          aria-label="Previous page"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
          <span>Prev</span>
        </Button>

        <span className="px-2 font-medium text-slate-300">
          Page {currentPage} of {totalPages}
        </span>

        <Button
          size="sm"
          variant="secondary"
          onClick={() => onPageChange(offset + limit)}
          disabled={currentPage >= totalPages || isLoading}
          aria-label="Next page"
        >
          <span>Next</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  );
};
