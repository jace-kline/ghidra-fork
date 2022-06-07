#ifndef __STREAMBUFS__
#define __STREAMBUFS__

#include <iostream>
#include <streambuf>

// https://wordaligned.org/articles/cpp-streambufs
// https://gcc.gnu.org/onlinedocs/libstdc++/manual/streambufs.html

// Takes two output buffers
// Passes write characters to both stored buffers & syncs them
// Used to "split" an output stream into 2
template <typename char_type, typename traits = std::char_traits<char_type> >
class basic_outteebuf : public std::basic_streambuf<char_type, traits>
{
public:
    typedef typename traits::int_type int_type;

    basic_outteebuf(std::basic_streambuf<char_type, traits> * sb1,
                 std::basic_streambuf<char_type, traits> * sb2)
      : sb1(sb1)
      , sb2(sb2)
    {
    }

private:    
    virtual int sync()
    {
        int const r1 = sb1->pubsync();
        int const r2 = sb2->pubsync();
        return r1 == 0 && r2 == 0 ? 0 : -1;
    }

    virtual int_type overflow(int_type c)
    {
        int_type const eof = traits::eof();

        if (traits::eq_int_type(c, eof))
        {
            return traits::not_eof(c);
        }
        else
        {
            char_type const ch = traits::to_char_type(c);
            int_type const r1 = sb1->sputc(ch);
            int_type const r2 = sb2->sputc(ch);

            return
                traits::eq_int_type(r1, eof) ||
                traits::eq_int_type(r2, eof) ? eof : c;
        }
    }

private:
    std::basic_streambuf<char_type, traits> * sb1;
    std::basic_streambuf<char_type, traits> * sb2;
};

// Takes an input buffer (reading) and an output buffer (writing)
// Each read character from input buffer is copied to output buffer
// The idea is to log an input stream to an output stream
template <typename char_type, typename traits = std::char_traits<char_type> >
class basic_inteebuf : public std::basic_streambuf<char_type, traits>
{
public:
    typedef typename traits::int_type int_type;

    basic_inteebuf(std::basic_streambuf<char_type, traits> * readbuf,
                 std::basic_streambuf<char_type, traits> * logbuf)
      : readbuf(readbuf)
      , logbuf(logbuf)
    {
    }

private:    
    virtual int_type underflow() {

        int_type res = readbuf->sbumpc();
        //  && !traits::eq(traits::to_char_type(res), '\n')
        if ((res != traits::eof())) {
            char ch = traits::to_char_type(res);
            logbuf->sputc(ch);
            this->setg(&ch, &ch, &ch + 1);
        }

        return res;
    }

private:
    std::basic_streambuf<char_type, traits> * readbuf;
    std::basic_streambuf<char_type, traits> * logbuf;
};

typedef basic_outteebuf<char> outteebuf;
typedef basic_inteebuf<char> inteebuf;

class outteestream : public std::ostream
{
public:
    // Construct an ostream which tees output to the supplied ostreams
    outteestream(std::ostream & o1, std::ostream & o2)
    : std::ostream(&tbuf), tbuf(o1.rdbuf(), o2.rdbuf()) {}
private:
    outteebuf tbuf;
};

class inteestream : public std::istream
{
public:
    // Construct an ostream which tees output to the supplied ostreams
    inteestream(std::istream & readstream, std::ostream & logstream)
    : std::istream(&tbuf), tbuf(readstream.rdbuf(), logstream.rdbuf()) {}
private:
    inteebuf tbuf;
};

#endif