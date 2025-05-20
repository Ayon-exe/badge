"use client";

import * as React from "react";
import axios from "axios";
import { Check, Plus, Search, Trash2, X } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useRouter } from "next/navigation";
import { useWatchlist } from "@/context/WatchlistContext";
import { useToast } from "@/hooks/use-toast";
import VersionAutocomplete from "./VersionAutocomplete";

export default function SymbolPicker() {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [results, setResults] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [activeTab, setActiveTab] = React.useState("all");
  const [version, setVersion] = React.useState("");
  const [actionLoading, setActionLoading] = React.useState(null);
  const { toast } = useToast();
  const router = useRouter();
  const {
    watchlist,
    activeWatchlistIndex,
    addToWatchlist,
    fetchWatchlist,
    removeFromWatchlist,
  } = useWatchlist();

  const handleVersionInput = (event) => {
    setVersion(event.value);
  }

  const isInWatchlist = React.useCallback(
    (type, value) => {

      return watchlist?.watchlists
        ?.flatMap(watchlist => watchlist.items) // Flatten the items from all watchlists
        ?.some(item => item[type] === value) ?? 
        false;
      //return watchlist?.watchlists[activeWatchlistIndex]?.items?.some(
      //  (item) => item[type] === value
      //) ?? false;
    },
    [watchlist, activeWatchlistIndex]
  );

  React.useEffect(() => {
      let isMounted = true; // Flag to track if the component is mounted
    const fetchResults = async () => {
      if (!query.trim()) {
         if (isMounted) {
        setResults(null);
        setError("");
         }
        return;
      }

      setLoading(true);
      try {
        const response = await axios.get(
          `${
            process.env.SERVER_URL
          }/api/cve/autocomplete?q=${encodeURIComponent(query)}`
        );

        if (isMounted) {
          if (response.data && Array.isArray(response.data.vendors) && 
            Array.isArray(response.data.products)) {
            setResults({
              vendors: response.data.vendors || [],
              products: response.data.products || [],
            });
            setError("");
          } else {
            setResults(null);
            setError("Invalid response format");
          }
        }
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : "Search failed";
         if (isMounted) {
        setError(errorMessage);
        setResults(null);
      }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    const debounceTimer = setTimeout(fetchResults, 200);
    return () => {
      clearTimeout(debounceTimer);
      isMounted = false;
    };
  }, [query]);

  const filteredResults = React.useMemo(() => {
    if (!results) return { vendors: [], products: [] };

    if (activeTab === "vendor") {
      return { vendors: results.vendors, products: [] };
    }
    if (activeTab === "product") {
      return { vendors: [], products: results.products };
    }
    return results;
  }, [results, activeTab]);

  const handleToggleSymbol = async (type, value) => {
    const itemId = `${type}-${value}`;
    setActionLoading(itemId);

    try {
      if (isInWatchlist(type, value)) {
        const success = await removeFromWatchlist(
          type,
          value,
          watchlist.watchlists[activeWatchlistIndex].name
        );
        if (success) {
          toast({
            title: "Success",
            description: "Item removed from watchlist",
          });
        }
      } else {
        const success = await addToWatchlist(
          type,
          value,
          watchlist.watchlists[activeWatchlistIndex].name,
          version
        );
        if (success) {
          toast({
            title: "Success",
            description: "Item added to watchlist",
          });
          await fetchWatchlist()
        }
      }
    } catch (err) {
      toast({
        title: "Error",
        description: err.message || "Failed to update watchlist",
        variant: "destructive",
      });
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Button variant="outline" onClick={() => setOpen(true)}>
        Add to Watchlist
      </Button>
      <DialogContent className="max-w-md bg-blue-950/30 backdrop-blur-md shadow-lg rounded-md">
        <DialogHeader>
          <DialogTitle>Add to Watchlist</DialogTitle>
        </DialogHeader>
        <div className="relative">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search vendors or products..."
            className="pl-8 w-full max-w-md truncate text-ellipsis"
            value={query}
            onChange={(e) => {
              const maxLength = 50; // adjust the value as needed
              if (e.target.value.length > maxLength) {
                setQuery(e.target.value.substring(0, maxLength));
              } else {
                setQuery(e.target.value);
              }
            }}
            maxLength={50} // adjust the value as needed
          />
        </div>
        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="justify-start w-full max-w-md">
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="vendor">Vendors</TabsTrigger>
            <TabsTrigger value="product">Products</TabsTrigger>
          </TabsList>
          <TabsContent value={activeTab} className="mt-0">
            <ScrollArea className="h-[300px] pr-4">
              {loading && (
                <div className="flex justify-center p-4">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
                </div>
              )}

              {error && (
                <div className="p-4 text-destructive text-sm text-center">
                  {error}
                </div>
              )}

              {!loading && !error && results && (
                <>
                  {filteredResults.vendors.length > 0 && (
                    <div className="my-4 max-w-md">
                      <h3 className="text-sm font-medium text-muted-foreground mb-2 px-2">
                        Vendors
                      </h3>
                      {filteredResults.vendors.map((vendor) => (
                        <div
                          key={`vendor-${vendor}`}
                          className="flex items-center justify-between py-2 hover:bg-accent rounded-md px-2"
                        >
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
                              {vendor[0]}
                            </div>
                            <div className="font-medium">{vendor}</div>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleToggleSymbol("vendor", vendor)}
                            disabled={actionLoading === `vendor-${vendor}`}
                          >
                            {actionLoading === `vendor-${vendor}` ? (
                              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary" />
                            ) : isInWatchlist("vendor", vendor) ? (
                              <Trash2 className="h-4 w-4" />
                            ) : (
                              <Plus className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}

                  {filteredResults.products.length > 0 && (
                    <div className="max-w-md">
                      <h3 className="text-sm font-medium text-muted-foreground mb-2 px-2">
                        Products
                      </h3>
                      {filteredResults.products.map((product) => (
                      <div
                        key={`product-${product}`}
                        className="flex items-center justify-between py-2 hover:bg-accent rounded-md px-2"
                      >
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
                            {product[0]}
                          </div>
                          <div className="font-medium">{product}</div>
                        </div>
                        <div className="ml-auto flex items-center">
                          {/* <VersionAutocomplete
                            product={product}
                            onChange={(version) => handleVersionInput({ value: version })}
                          /> */}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleToggleSymbol("product", product)}
                            disabled={actionLoading === `product-${product}`}
                          >
                            {actionLoading === `product-${product}` ? (
                              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary" />
                            ) : isInWatchlist("product", product) ? (
                              <Trash2 className="h-4 w-4" />
                            ) : (
                              <Plus className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </div>
                    ))}
                    </div>
                  )}

                  {!filteredResults.vendors.length &&
                    !filteredResults.products.length &&
                    query && (
                      <div className="p-4 text-center text-muted-foreground">
                        No results found
                      </div>
                    )}
                </>
              )}
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}