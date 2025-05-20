import React, { useState, useEffect } from 'react';
import { useWatchlist } from '@/context/WatchlistContext';
import { ChevronLeft, ChevronRight, Edit, Check } from 'lucide-react';

const PAGE_LIMIT_OPTIONS = [10, 20, 30];

const Sidebar = (props) => {
  const { watchlist, activeWatchlistIndex, setActiveWatchlistIndex } = useWatchlist();
  const [limit, setLimit] = useState(PAGE_LIMIT_OPTIONS[0]);
  const [sortBy, setSortBy] = useState("lowest-scores-first");
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedItems, setSelectedItems] = useState([]);
  const [updateClicked, setUpdateClicked] = useState({}); // new state variable
  const [newItem, setNewItem] = useState({}); // new state variable

  useEffect(() => {
    if (watchlist.watchlists.length > 0) {
      // setCurrentIndex(0);
      // setActiveWatchlistIndex(0);
      setSelectedItems([]);
    }
  }, [watchlist.watchlists]);

  const handlePrevClick = () => {
    if (watchlist.watchlists.length > 0) {
      setCurrentIndex(() => (activeWatchlistIndex - 1 + watchlist.watchlists.length) % watchlist.watchlists.length);
      setSelectedItems([]);
    }
    setActiveWatchlistIndex(currentIndex);
    // props.setCurrentWatchlist(watchlist.watchlists[currentIndex]);
    props.setPage(1);
  };

  const handleNextClick = () => {
    if (watchlist.watchlists.length > 0) {
      setCurrentIndex(() => (activeWatchlistIndex + 1) % watchlist.watchlists.length);
      setSelectedItems([]);
    }
    // props.setCurrentWatchlist(watchlist.watchlists[currentIndex]);
    setActiveWatchlistIndex(currentIndex);
    props.setPage(1);
  };

  const handleItemClick = (item) => {
    if (selectedItems.includes(item)) {
      setSelectedItems(selectedItems.filter((i) => i !== item));
    } else {
      setSelectedItems([...selectedItems, item]);
    }
    // setActiveWatchlistIndex(currentIndex);
  };

  const handleUpdateClick = (item) => {
    setUpdateClicked((prevUpdateClicked) => ({
      ...prevUpdateClicked,
      [item.product]: !prevUpdateClicked[item.product],
    }));
  };

  const handleAddItemClick = (item) => {
    // add new item to watchlist
    const newItemObj = { product: newItem[item.product].trim() };
    watchlist.watchlists[currentIndex].items.push(newItemObj);
    setSelectedItems([...selectedItems, newItemObj]);
    setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: '' }));
    setUpdateClicked((prevUpdateClicked) => ({ ...prevUpdateClicked, [item.product]: false }));
  };

  return (
    <div className="w-64 bg-slate-950/75 backdrop-blur-sm p-4 min-h-[50vh] border border-white/20 rounded-lg shadow-lg">
      <h2 className="text-lg font-bold mb-4">Filter by</h2>
      {watchlist.watchlists.length > 0 ? (
        <div className="flex items-center mb-4">
          <button className="border rounded-md px-3 py-2" onClick={handlePrevClick}>
            <ChevronLeft className="w-4 h-4" />
          </button>
          <h3 className="text-sm font-bold mx-2 word-wrap">
            {watchlist.watchlists[currentIndex].name}
          </h3>
          <button className="border rounded-md px-3 py-2" onClick={handleNextClick}>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <p>No watchlists available.</p>
      )}
      {watchlist.watchlists.length > 0 ? (
        <div className="flex flex-col">
          <ul>
          {watchlist.watchlists[currentIndex].items.map((item, idx) => (
  item.product ? (
    <li key={idx} className="flex flex-col mb-4">
      <div className="flex items-center">
        <input
          type="checkbox"
          value={item.product?.trim()}
        />
        <span className="ml-2">
          {item.product?.trim()}
        </span>
        <button className="ml-2 p-1" onClick={() => handleUpdateClick(item)}>
          <Edit className="w-4 h-4" />
        </button>
      </div>
      {updateClicked[item.product] ? (
        <div className="mt-2 ml-4">
          <input
            type="text"
            className="bg-background px-2 border rounded-md w-20"
            value={newItem[item.product]}
            onChange={(e) => setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: e.target.value }))}
            placeholder="Version"
          />
          <button className="ml-2 p-1 mt-2">
            <Check className="w-4 h-4" />
          </button>
        </div>
      ) : null}
    </li>
  ) : null
))}
          </ul>
        </div>
      ) : (
        <p>No items available.</p>
      )}
    </div>
  );
};

export default Sidebar;