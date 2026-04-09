const exitWithFatalError = (label, error) => {
    console.error(`[startup] ${label}`);
    console.error(error);
    process.exit(1);
};
process.on("uncaughtException", (error) => {
    exitWithFatalError("Uncaught exception", error);
});
process.on("unhandledRejection", (error) => {
    exitWithFatalError("Unhandled promise rejection", error);
});
import("./server.js").catch((error) => {
    exitWithFatalError("Server bootstrap failed", error);
});
export {};
