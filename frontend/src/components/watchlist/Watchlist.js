// WatchlistSidebar.js
import * as React from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Trash2, Building2, Package, Loader2, Tag, Contact, CalendarPlus,Sigma,BriefcaseMedical, Plus, Pencil, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";
import { useToast } from "@/hooks/use-toast";
import { useWatchlist } from "@/context/WatchlistContext";
import Link from "next/link";
import WatchlistPopup from "@/components/watchlist/WatchlistPopup";
import ConfirmationModal from "@/components/watchlist/ConfirmationModal";

export default function WatchlistList() {
  const [isHoveringEditDelete, setIsHoveringEditDelete] = React.useState(false);
  const [isModalOpen, setIsModalOpen] = React.useState(false);
  const [itemToDelete, setItemToDelete] = React.useState(null);
  const [deletingItem, setDeletingItem] = React.useState(null);
  const [watchlistTransition, setWatchlistTransition] = React.useState(null);
  const { toast } = useToast();
  const router = useRouter();
  const {
    updateWatchlist,
    activeWatchlistIndex,
    removeWatchlist,
    createNewWatchlist,
    watchlist,
    watchlistStats,
    loading,
    error,
    fetchWatchlist,
    fetchWatchlistStats,
    removeFromWatchlist,
    setActiveWatchlistIndex,
  } = useWatchlist();

  React.useEffect(() => {
    fetchWatchlist();
  }, [fetchWatchlist]);

  React.useEffect(() => {
    fetchWatchlistStats();
  }, [fetchWatchlistStats]);

  const truncateText = (text, maxLength) => {
    if (text.length > maxLength) {
      return text.substring(0, maxLength) + '...';
    }
    return text;
  };

  const handleCreateWatchlist = async () => {
    const newWatchlistName = prompt("Enter name for the watchlist:");
    if (!newWatchlistName) {
      toast({ title: "Error", description: "Watchlist name cannot be empty." });
      return;
    }

    try {
      await createNewWatchlist(newWatchlistName);
      toast({ title: "Success", description: "Watchlist created successfully." });
      setActiveWatchlistIndex(watchlist.watchlists.length);
    } catch (error) {
      toast({ title: "Error", description: "Failed to create watchlist." });
    }
  };

  const handleRemoveFromWatchlist = async (type, value, watchlistName) => {
    const itemId = `${type}-${value}`;
    setDeletingItem(itemId);
    try {
      await removeFromWatchlist(type, value, watchlistName);
      toast({ title: "item removed", description: "The item has been successfully removed from the watchlist." });
    } finally {
      setDeletingItem(null);
    }
  };

  const handleRemoveWatchlist = async (watchlistName) => {
    setItemToDelete(watchlistName);
    setIsModalOpen(true);
  };

  const confirmDelete = async () => {
    try {
      await removeWatchlist(itemToDelete);
      toast({ title: "Watchlist removed", description: "The watchlist has been successfully removed." });
      setActiveWatchlistIndex(activeWatchlistIndex === 0 ? activeWatchlistIndex : activeWatchlistIndex - 1);
    } catch (error) {
      toast({ title: "Error", description: "Failed to remove watchlist." });
    }
    setIsModalOpen(false);
    setItemToDelete(null);
  };

  const handleWatchlistSwitch = (index) => {
    if (index !== activeWatchlistIndex) {
      setWatchlistTransition("out");
      setTimeout(() => {
        setActiveWatchlistIndex(index);
        setWatchlistTransition("in");
      }, 500);
    }
  };

  const handleEditWatchlist = async (watchlistName) => {
    const newWatchlistName = prompt("Enter a new name for the watchlist:");
    if (!newWatchlistName) {
      toast({ title: "Error", description: "Watchlist name cannot be empty." });
      return;
    }

    try {
      const updatedWatchlist = await updateWatchlist(watchlistName, newWatchlistName);
      const updatedWatchlists = watchlist.watchlists.map((watchlist) => {
        if (watchlist.name === watchlistName) {
          return { ...watchlist, name: newWatchlistName };
        }
        return watchlist;
      });
      setWatchlist({ ...watchlist, watchlists: updatedWatchlists });
    } catch (error) {
      toast({ title: "Error", description: "Failed to update watchlist name." });
    }
  };

  const allItems = watchlist?.watchlists[activeWatchlistIndex]?.items.map((item) => {
    const type = item.vendor ? "vendor" : "product";
    const value = item.vendor || item.product;
    const stats = watchlistStats?.find((stat) => stat._id === value);

    const cveAddedThisWeek = stats ? stats.cveAddedThisWeek : 0;
    const totalCVE = stats ? stats.totalCVE : 0;
    const patchesAvailable = stats ? stats.patchesAvailable : 0;

    return { type, value, cveAddedThisWeek, totalCVE, patchesAvailable };
  });

  function abbreviateNumber(num) {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'k';
    } else {
      return num.toString();
    }
  }

  if (loading) {
    return (
      <div className="w-full h-[715px] bg-slate-950/75 backdrop-blur-sm p-4 rounded-lg shadow-lg">
        <Loader2 className="h-8 w-8 items-center justify-between animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-64 bg-slate-950/75 backdrop-blur-sm p-4">
        <p className="text-destructive">Error loading data: {error}</p>
        <Button variant="outline" className="mt-4" onClick={() => fetchWatchlist(true)}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="w-full h-auto sm:h-[715px] max-h-[600px] sm:max-h-none overflow-y-auto sm:overflow-y-hidden bg-slate-950/75 backdrop-blur-sm p-4 border border-white/20 rounded-lg shadow-lg">
      <div className="flex gap-4 mb-2 items-center justify-between group relative">
        <Button
          variant="ghost"
          className="text-white bg-blue font-bold rounded-lg"
          onClick={() => handleWatchlistSwitch(activeWatchlistIndex - 1)}
          disabled={activeWatchlistIndex === 0}
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center justify-between group relative">
          {/* Watchlist name */}
          <div className="text-white font-bold rounded-lg group-hover:invisible transition-opacity duration-150">
            {watchlist?.watchlists[activeWatchlistIndex]?.name}
          </div>
  
          {/* Buttons to add, edit, and remove watchlist */}
          <div className="invisible group-hover:visible transition-opacity duration-150 absolute top-0 left-1/2 transform -translate-x-1/2 flex space-x-2">
            <Button variant="ghost" className="ml-2" onClick={handleCreateWatchlist}>
              <Plus className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              className="ml-2"
              onClick={() => handleEditWatchlist(watchlist?.watchlists[activeWatchlistIndex]?.name)}
            >
              <Pencil className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              className="ml-2"
              onClick={() => handleRemoveWatchlist(watchlist?.watchlists[activeWatchlistIndex]?.name)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <Button
          variant="ghost"
          className="text-white font-bold rounded-lg"
          onClick={() => handleWatchlistSwitch(activeWatchlistIndex + 1)}
          disabled={activeWatchlistIndex === watchlist.watchlists.length - 1}
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
  
      <div className="w-full rounded-lg shadow-md">
        <table className="table-auto w-full">
          <thead className="bg-[#00B3F3] text-black font-bold cursor-pointer text-capitalize h-24px">
            <tr>
              <th className="p-2 flex justify-center items-center font-semibold text-sm uppercase tracking-wider cursor-pointer group">
                <Contact className="text-black"/>
                <span className="absolute hidden group-hover:block text-xs bg-black text-white p-1 rounded-md" style={{ top: '70px' }}>
                  Name
                </span>
              </th>
              <th className="p-2 text-center font-semibold text-sm uppercase tracking-wider cursor-pointer group">
                <Tag className="text-black"/>
                <span className="absolute hidden group-hover:block text-xs bg-black text-white p-1 rounded-md" style={{ top: '70px' }}>
                  Type
                </span>
              </th>
              <th className="p-2 text-center font-semibold text-sm uppercase tracking-wider cursor-pointer group">
                <CalendarPlus className="text-black" />
                <span className="absolute hidden group-hover:block text-xs bg-black text-white p-1 rounded-md" style={{ top: '70px' }}>
                  CVE added this week
                </span>
              </th>
              <th className="p-2 text-center font-semibold text-sm uppercase tracking-wider cursor-pointer group">
                <Sigma className="text-black" />
                <span className="absolute hidden group-hover:block text-xs bg-black text-white p-1 rounded-md" style={{ top: '70px' }}>
                  Total CVE
                </span>
              </th>
              <th className="p-2 text-center font-semibold text-sm uppercase tracking-wider cursor-pointer group">
                <BriefcaseMedical className="text-black" />
                <span className="absolute hidden group-hover:block text-xs bg-black text-white p-1 rounded-md" style={{ top: '70px' }}>
                  Patches available
                </span>
              </th>
              <th className="p-2 text-center font-semibold text-sm uppercase tracking-wider">
              </th>
            </tr>
          </thead>
          <tbody className="w-full overflow-x-hidden sm:scrollbar-thin sm:scrollbar-thumb-rounded sm:scrollbar-thumb-gray-500 sm:scrollbar-track-gray-100">
            {allItems?.length === 0 ? (
              <tr className="bg-[#03055B14] hover:bg-[#007A9E] hover:text-white h-20px">
                <td colSpan={6} className="p-2 text-center text-sm">
                  <WatchlistPopup />
                </td>
              </tr>
            ) : (
              <>
                {allItems?.map(({ type, value, cveAddedThisWeek, totalCVE, patchesAvailable}, index) => (
                  <tr
                    key={index}
                    className={`transition duration-150 rounded-xl backdrop-blur-sm ${
                      index % 2 === 0 ? "bg-[#03055B14]" : "bg-[#00000014]"
                    } hover:bg-[#007A9E] hover:text-white h-20px`}
                  >
                    <td className="p-0 text-center text-sm break-words">
                      <Link
                        href={type === "vendor" ? `/vendor/${value}` : `/product/${value?.replaceAll(/\s+/g, "-")}`}
                      >
                        {truncateText(value, 12)}
                      </Link>
                    </td>
                    <td className="p-0 text-center text-sm">
                      {type === "vendor" ? (
                        <div className="flex justify-center">
                          <Building2 className="h-4 w-4 text-blue-500" />
                        </div>
                      ) : (
                        <div className="flex justify-center">
                          <Package className="h-4 w-4 flex text-green-500" />
                        </div>
                      )}
                    </td>
                    <td className="p-0 text-center text-sm">{abbreviateNumber(cveAddedThisWeek)}</td>
                    <td className="p-0 text-center text-sm">{abbreviateNumber(totalCVE)}</td>
                    <td className="p-0 text-center text-sm">{abbreviateNumber(patchesAvailable)}</td>
                    <td className="p-0 text-center text-sm">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="opacity-100 transition-opacity"
                        onClick={() => handleRemoveFromWatchlist(type, value, watchlist.watchlists[activeWatchlistIndex].name)}
                        disabled={deletingItem === `${type}-${value}`}
                      >
                        {deletingItem === `${type}-${value}` ? (
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    </td>
                  </tr>
                ))}
                <tr className="bg-[#03055B14] hover:bg-[#007A9E] hover:text-white">
                  <td colSpan={6} className="p-2 text-center text-sm">
                    <WatchlistPopup />
                  </td>
                </tr>
              </>
            )}
          </tbody>
        </table>
      </div>
      
      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onConfirm={confirmDelete}
        itemName={itemToDelete}
      />
    </div>
  );
}