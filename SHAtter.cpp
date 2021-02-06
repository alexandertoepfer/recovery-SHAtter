/*   \"/    ____  ____  _     _____  _____   _____ ____  ____  ____  _____   ____  _     ____  _
 * .-.".-. /  __\/  __\/ \ /\/__ __\/  __/  /    //  _ \/  __\/   _\/  __/  / ___\/ \ /|/  _ \/ \
 *  '   '  | | //|  \/|| | ||  / \  |  \    |  __\| / \||  \/||  /  |  \    |    \| |_||| / \|| |
 *  .   .  | |_\\|    /| \_/|  | |  |  /_   | |   | \_/||    /|  \__|  /_   \___ || | ||| |-||| |
 * .-.".-. \____/\_/\_\\____/  \_/  \____\  \_/   \____/\_/\_\\____/\____\  \____/\_/ \|\_/ \|\_/
 *   \"/
 * Alexander
 * Toepfer 2020
 */
#include <string>
#include <vector>
#include <array>
#include <sstream>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <future>
#include <stdio.h>
#include <stdint.h>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#define PASSLEN 4
#define THREADS 12
#define CHARSETSIZE 84

std::string sha1( std::string source ) {
	std::string hash;
	CryptoPP::SHA1 sha1;
	// Pipeline might be able to still be optimized without HexEncoder
	CryptoPP::StringSource( source, true, new CryptoPP::HashFilter( sha1,
		                    new CryptoPP::HexEncoder( new CryptoPP::StringSink( hash ) ) ) );
	return hash;
}

// Reverse lookup for charset to increment full size strings later
std::array< unsigned int, 128 > reverseLookup( std::array< char, CHARSETSIZE >& charset, bool verbose ) {
	std::array< unsigned int, 128 > charset_reverse;
	std::fill( charset_reverse.begin(), charset_reverse.end(), 0 );
	for( int i = 0; i < CHARSETSIZE; ++i ) {
		charset_reverse[ ( int )charset[ i ] ] = i;
	}
	if( verbose ) {
		std::cout << '{';
		for( int i = 0; i < charset_reverse.size(); ++i ) {
			if( !( i % 6 ) && i > 0 )
				std::cout << std::endl;
			std::cout << charset_reverse[ i ] << ',' << ' ';
		}
		std::cout << '}';
	}
	return charset_reverse;
}

// Recreate the string for an amount of iterations of the algorithm
std::string guessToString( unsigned long long guess, const std::array< char, CHARSETSIZE >& charset ) {
	std::string res( PASSLEN, '\0' );
	unsigned long long rem = 1;
	int index = 0, i, chars = 1;
	for( i = 1; i < PASSLEN; i++ ) {
		rem *= CHARSETSIZE;
	}
	for( i = PASSLEN - 1; i >= 0; --i ) {
		index = guess / rem;
		guess = guess % rem;
		rem /= CHARSETSIZE;
		res[ i ] = charset[ index ];
	}
	std::string tmp = res;
	rem = 1;
	/* Remove padded spaces */
	for( i = 0; i < PASSLEN; ++i, ++chars ) {
		rem *= CHARSETSIZE;
		if( guess < rem )
			break;
	}
	for( i = PASSLEN - 1; i > chars - 1; --i ) {
		if( res[ i ] == ' ' )
			tmp.erase( i, 1 );
		else break;
	}
	return tmp;
}

// Can't use STL here because doubles are inconvenient
unsigned int pow( unsigned int base, int exp ) {
	unsigned int res = 1;
	for( ; exp > 0; --exp )
		res *= base;
	return res;
}

unsigned long long stringToGuess( std::string str, unsigned int size,
								  const std::array< unsigned int, 128 >& charsetr ) {
	// Polynomial to create specific guess
	// Example for "abcd..." with i(...) being the index of
	/*
		f(a,b,c,d,...) = i(a)*pow(s,0) + i(b)*pow(s,1) + i(c)*pow(s,2) + i(d)*pow(s,3) + ...
	*/
	unsigned long long res = 0;
	for( int i = 0; i < str.size(); ++i )
		res += charsetr[ str[ i ] ] * pow( size, i );
	return res;
}

// Function to produce guesses for a certain range with (value,guesses]
// where value is the starting string and guesses the iteration of the last guess
int getGuesses( std::string& value, std::string hash, const unsigned int guesses, std::atomic< unsigned int >& counter,
	            std::promise< std::string >&& prom, std::atomic< bool >& stop, const std::array< char, CHARSETSIZE >& charset,
	            const std::array< unsigned int, 128 >& charsetr, std::chrono::steady_clock::time_point& time ) {
	unsigned int i, j, k = 0;
	std::string testhash;
	CryptoPP::SHA1 sha1;

	// Starting iteration for passed string
	if ( !value.empty() )
		k = stringToGuess( value.c_str(), CHARSETSIZE, charsetr );

	for( j = 0; j < guesses; ++j, ++counter ) {
		// If thread should be forcefully stopped
		if( stop ) {
			// Indicate no string found and continuity broken
			prom.set_value( "" );
			return -1;
		}

		// Reset characters which overflow in next iteration
		for( i = 0; i < value.size(); ++i ) {
			if( value[ i ] != ')')
				break;
			else
				value[ i ] = ' ';
		}

		// Increment character after resetting
		value[ i ] = charset[ charsetr[ value[ i ] ] + 1 ];
		testhash.clear();
		CryptoPP::StringSource( value.c_str(), true, new CryptoPP::HashFilter( sha1,
			                    new CryptoPP::HexEncoder( new CryptoPP::StringSink( testhash ) ) ) );

		if( strcmp( hash.c_str(), testhash.c_str() ) )
			continue;
		// Found string that produces hash
		else {
			time = std::chrono::high_resolution_clock::now();
			// Stop all currently running threads
			stop = true;
			prom.set_value( value );
			// Return next iteration
			return j + /* starting string */k + 1;
		}
	}
	// No string found to recreate hash
	prom.set_value( "" );
	return -1;
}

int getGuessesVerbose( std::string& value, std::string hash, const unsigned int guesses, std::atomic< unsigned int >& counter,
	                   std::promise< std::string >&& prom, std::atomic< bool >& stop, const std::array< char, CHARSETSIZE >& charset,
	                   const std::array< unsigned int, 128 >& charsetr, std::chrono::steady_clock::time_point& time ) {
	unsigned int i, j, k = 0;
	std::string testhash;
	CryptoPP::SHA1 sha1;
	if ( !value.empty() )
		k = stringToGuess( value.c_str(), CHARSETSIZE, charsetr );
	for( j = 0; j < guesses; ++j, ++counter) {
		if( stop ) {
			prom.set_value( "" );
			return -1;
		}
		for( i = 0; i < value.size(); ++i ) {
			if( value[ i ] != ')' )
				break;
			else
				value[ i ] = ' ';
		}
		value[ i ] = charset[ charsetr[ value[ i ] ] + 1 ];
		testhash.clear();
		CryptoPP::StringSource( value.c_str(), true, new CryptoPP::HashFilter( sha1,
							    new CryptoPP::HexEncoder( new CryptoPP::StringSink( testhash ) ) ) );
		// Print current value and testhash
		printf( "\"%s\" %s\n", value.c_str(), testhash.c_str() );
		if( strcmp( hash.c_str(), testhash.c_str() ) )
			continue;
		else {
			time = std::chrono::high_resolution_clock::now();
			stop = true;
			prom.set_value( value );
			return j + k + 1;
		}
	}
	prom.set_value( "" );
	return -1;
}

void bruteSHAtter( std::string hash, int guesses, int parallel, std::array< char, CHARSETSIZE >& charset ) {
	// For looking up indices of characters
	std::array< unsigned int, 128 > charsetr = reverseLookup( charset, false );

	std::cout << "Hash: " << "SHA-1$" << hash << std::endl;
	std::cout << "Guesses: " << guesses << std::endl;

	// Divide into whole number parts for each thread
	unsigned int part = guesses / parallel;

	// Strings and iterations for each thread to start with
	std::vector< int > startings;
	std::vector< std::string > startingstrings;
	std::vector< std::thread > threads;

	// Amount of threads and indicator to stop process
	std::atomic< unsigned int > counter = 0;
	std::atomic< bool > stop_all = false;

	// Prepare ranges for each thread to run through
	std::cout << "Threads: " << parallel << std::endl;
	//std::cout << "Thread Strings: {" << std::endl;
	for( unsigned int i = 0; i < parallel; i++ ) {
		if ( !(i % 6) && i > 0 )
			std::cout << std::endl;
		std::string tmp = guessToString( part * i, charset );
		startingstrings.push_back( tmp );
		//std::cout << i + 1 << ':' << ' ' << '\"' << tmp << '\"' << ", ";
		startings.push_back( stringToGuess( tmp.c_str(), CHARSETSIZE, charsetr ) );
	}
	//std::cout << std::endl << '}' << std::endl;

	std::vector< std::promise< std::string > > proms( parallel );
	std::vector< std::future< std::string > > results( parallel );
	// Mechanism to access the result of asynchronous operations
	for( int i = 0; i < parallel; i++ )
		results[ i ] = proms[ i ].get_future();
	std::cout << "Press Enter to Start" << std::endl;
	std::cin.get();

	// Measure time taken for threads
	std::chrono::steady_clock::time_point time1 = std::chrono::high_resolution_clock::now(), time2;

	// Spawn threads to start brute force
	for( int i = 0; i < parallel; ++i ) {
		std::thread t( &getGuesses, std::ref( startingstrings[ i ] ), std::ref( hash ), part, std::ref( counter ),
			           std::move( proms[ i ] ), std::ref( stop_all ), std::ref( charset ),
			           std::ref( charsetr ), std::ref( time2 ) );
		threads.emplace_back( std::move( t ) );
	}

	// Waiting for threads to finish
	for( int i = 0; i < threads.size(); i++ )
		threads[ i ].join();

	std::string val = "";
	// Checking for results
	for( int i = 0; i < parallel; i++ ) {
		try {
			std::string tmp = results[ i ].get();
			if ( !tmp.empty() )
				val = tmp;
		}
		catch ( ... ) {}
	}
	std::chrono::duration< double > d = time2 - time1;
	// If string was recovered to produce hash
	if ( !val.empty() )
		std::cout << "Recovered: " << val << std::endl;
	std::cout << "Hashes: " << counter << std::endl;
	std::cout << "Runtime: " << d.count() << 's' << std::endl;
}

void dictSHAtter( std::string hash, int guesses, int parallel, std::string filename ) {
	std::cout << "Hash: " << "SHA-1$" << hash << std::endl;
	std::cout << "Guesses: " << guesses << std::endl;
	std::cout << "Threads: " << parallel << std::endl;
	std::cout << "Dict: " << filename << std::endl;
	std::cout << "Press Enter to Start" << std::endl;
	std::cin.get();

	// TODO Multi-threaded
	if( parallel - 1 ) {
		std::cout << "Multi-threaded Dictionary attack currently unsupported" << std::endl;
		return;
	}
	std::ifstream infile(filename.c_str());
	if( !( infile.good() ) ) {
		std::cout << "File \"" << filename << "\" not found" << std::endl;
		return;
	}
	CryptoPP::SHA1 sha1;
	std::string line, testhash, res = "";
	std::chrono::steady_clock::time_point time1 = std::chrono::high_resolution_clock::now(), time2;
	int counter = 0;
	while( std::getline( infile, line ) ) {
		if( counter == guesses - 1 )
			break;
		testhash.clear();
		CryptoPP::StringSource( line.c_str(), true, new CryptoPP::HashFilter( sha1,
			                    new CryptoPP::HexEncoder( new CryptoPP::StringSink( testhash ) ) ) );
		counter++;
		if( strcmp( hash.c_str(), testhash.c_str() ) )
			continue;
		else {
			res = line;
			break;
		}
	}
	time2 = std::chrono::high_resolution_clock::now();
	std::chrono::duration< double > d = time2 - time1;
	if( !( res.empty() ) )
		std::cout << "Recovered: " << res << std::endl;
	std::cout << "Hashes: " << counter << std::endl;
	std::cout << "Runtime: " << d.count() << 's' << std::endl;
}

int main() {
	std::array< char, CHARSETSIZE > charset = {
		' ','0','1','2','3','4',
		'5','6','7','8','9','a',
		'b','c','d','e','f','g',
		'h','i','j','k','l','m',
		'n','o','p','q','r','s',
		't','u','v','w','x','y',
		'z','A','B','C','D','E',
		'F','G','H','I','J','K',
		'L','M','N','O','P','Q',
		'R','S','T','U','V','W',
		'X','Y','Z','.','!','*',
		'@','-','_','$','#',',',
		'/','+','?',';','%','~',
		'=','&','[',']','(',')'
	};

	// Entry for testing
	/*
	std::array< unsigned int, 128 > charsetr = reverseLookup(charset, false);
	std::cout << '"' << guessToString(10000000, charset) << '"' << std::endl;
	std::cout << '"' << stringToGuess("Pi+f", CHARSETSIZE, charsetr) << '"' << std::endl;
	std::cout << '"' << sha1("passed") << '"' << std::endl;
	std::cin.get();
	*/

	// Multi-threaded Brute Force attack
	// Permutation of characters can be used as guesses
	// Assume 1-4 character password for hash (CHARSLEN^4)-1
	bruteSHAtter( "7969A66BE4D694B6C6126BCB2F81533E69E913CB", /* divisible as integer by threads */49787135 + 1, THREADS, charset );
	std::cin.get();

	// Single-threaded dictionary attack
	dictSHAtter( "6A9F6C3FFF9581A22EF10CABD544143E37C61B4F", 14344326, 1, "rockyou.txt" );
	// Passwords have to be seperated by \n
	// Guesses equals to amount of lines read from dictionary
	std::cin.get();

	return 0;
}
