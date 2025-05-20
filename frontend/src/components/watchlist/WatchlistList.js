"use client"

import * as React from "react"
import { Trash2, Building2, Package } from 'lucide-react'
import { Button } from "@/components/ui/button"
import { useRouter } from "next/navigation"
import { useToast } from "@/hooks/use-toast"
import { useWatchlist } from "@/context/WatchlistContext"
import Link from "next/link"

export default function WatchlistList() {
  const [deletingItem, setDeletingItem] = React.useState(null)
  const { toast } = useToast()
  const router = useRouter()
  const { watchlist, loading, error, fetchWatchlist, removeFromWatchlist } = useWatchlist()

  React.useEffect(() => {
    fetchWatchlist()
  }, [fetchWatchlist])

  const handleRemoveFromWatchlist = async (type, value) => {
    const itemId = `${type}-${value}`
    setDeletingItem(itemId)
    try {
      await removeFromWatchlist(type, value)
    } finally {
      setDeletingItem(null)
    }
  }

  const allItems = watchlist.watching.map(item => {
    const type = item.vendor ? 'vendor' : 'product'
    const value = item.vendor || item.product
    return { type, value }
  })

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex justify-center items-center min-h-[400px]">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="container mx-auto p-6">
        <div className="text-center">
          <h2 className="text-lg font-semibold mb-2">Error Loading Watchlist</h2>
          <p>{error}</p>
          <Button 
            variant="outline" 
            className="mt-4"
            onClick={() => fetchWatchlist(true)}
          >
            Try Again
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6">
           
      {allItems.length === 0 ? (
        <div className="text-center text-muted-foreground py-8">
          <p>No items in your watchlist</p>
        </div>
      ) : (
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {allItems.map(({ type, value }) => (
            <div
              key={`${type}-${value}`}
              className="relative group bg-background rounded-lg p-6 hover:shadow-md transition-all"
            >
                {type === 'vendor' ?
                <Link href={`/vendor/${value}`}>
                    <div className="flex flex-col gap-2">
                <h2 className="text-xl font-semibold">{value}</h2>
                <div className="flex gap-6">
                  <div className="flex items-center gap-2 text-sm">
                    {type === 'vendor' ? (
                        <>
                        <Building2 className="h-4 w-4 text-blue-500" />
                        <span className="text-muted-foreground">Vendor</span>
                      </>
                    ) : (
                        <>
                        <Package className="h-4 w-4 text-green-500" />
                        <span className="text-muted-foreground">Product</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
                </Link>
                :
                <Link href={`/product/${value.replaceAll(
                    /\s+/g,
                    "-"
                  )}`}>
                    <div className="flex flex-col gap-2">
                <h2 className="text-xl font-semibold">{value}</h2>
                <div className="flex gap-6">
                  <div className="flex items-center gap-2 text-sm">
                    {type === 'vendor' ? (
                        <>
                        <Building2 className="h-4 w-4 text-blue-500" />
                        <span className="text-muted-foreground">Vendor</span>
                      </>
                    ) : (
                        <>
                        <Package className="h-4 w-4 text-green-500" />
                        <span className="text-muted-foreground">Product</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
              </Link>
                }

              <Button
                variant="ghost"
                size="icon"
                className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={() => handleRemoveFromWatchlist(type, value)}
                disabled={deletingItem === `${type}-${value}`}
              >
                {deletingItem === `${type}-${value}` ? (
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary" />
                ) : (
                  <Trash2 className="h-4 w-4" />
                )}
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

