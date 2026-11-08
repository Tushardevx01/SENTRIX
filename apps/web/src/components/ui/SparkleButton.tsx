'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Github, Star } from 'lucide-react';

export default function SparkleButton() {
  const [isHovered, setIsHovered] = useState(false);

  const handleClick = () => {
    window.open('https://github.com/Tushardevx01/SENTRIX/', '_blank', 'noopener,noreferrer');
  };

  return (
    <motion.button
      type="button"
      onClick={handleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.96 }}
      className="relative flex items-center justify-center text-black dark:text-white h-[36px] px-4 sm:px-5 rounded-[40px] bg-neutral-100 hover:bg-neutral-200 dark:bg-white/[0.04] dark:hover:bg-white/[0.08] border border-neutral-300 dark:border-white/10 cursor-pointer transition-colors duration-150 shadow-xs"
      title="Star SENTRIX on GitHub"
    >
      <div className="relative w-[16px] h-[16px] flex items-center justify-center shrink-0">
        <AnimatePresence mode="popLayout" initial={false}>
          {!isHovered ? (
            <motion.div
              key="icon1"
              initial={{ y: -15, opacity: 0, scale: 0.8 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: -15, opacity: 0, scale: 0.8 }}
              transition={{ type: 'spring', stiffness: 600, damping: 28 }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <Github className="w-4 h-4 text-black dark:text-white" />
            </motion.div>
          ) : (
            <motion.div
              key="icon2"
              initial={{ y: 15, opacity: 0, scale: 0.8 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: 15, opacity: 0, scale: 0.8 }}
              transition={{ type: 'spring', stiffness: 600, damping: 28 }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <Star className="w-4 h-4 text-yellow-500 dark:text-yellow-400 fill-yellow-400" />
              <motion.div
                initial={{ opacity: 0, scale: 0, rotate: -45, y: 10 }}
                animate={{ opacity: 1, scale: 1, rotate: 0, y: 0 }}
                exit={{ opacity: 0, scale: 0, rotate: 45, y: 10 }}
                transition={{ type: 'spring', stiffness: 600, damping: 28, delay: 0.05 }}
                className="absolute -top-3 -right-2"
              >
                <svg className="w-2.5 h-2.5 text-yellow-400" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 2l2.4 7.6H22l-6.2 4.5 2.4 7.6-6.2-4.5-6.2 4.5 2.4-7.6L2 9.6h7.6z" />
                </svg>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <span className="font-medium tracking-tight text-[12px] sm:text-[13px] ml-2">Star on GitHub</span>
    </motion.button>
  );
}

export { SparkleButton };

