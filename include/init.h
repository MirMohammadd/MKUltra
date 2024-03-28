#ifndef INIT_H
#define INIT_H


class InitPacket{
    public:
        InitPacket();
        ~InitPacket();

        void store(char* argv[],int len)
};

#endif // INIT_H