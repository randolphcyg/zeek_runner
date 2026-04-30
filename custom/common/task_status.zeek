export {
    module TaskStatus;
    redef enum Log::ID += { LOG };

    type Info: record {
        completedTime: string &log;
    };
}
