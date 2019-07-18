#include <iostream>
using namespace std;

class Phone
{
public :
	Phone()
	{}
	virtual ~Phone()
	{}
	virtual void showDecorate()
	{}
};
class iPhone  : public Phone  //具体手机类
{
private:
	string name;
public:
	iPhone(string _name)
		:name(_name)
	{}
	~iPhone()
	{}
	void showDecorate()
	{
		cout << name<<"的装饰"<< endl;
	}
};
class NokiaPhone : public  Phone
{
private:
	string name;
public :
	NokiaPhone(string _name)
		:name(_name)
	{}
	~NokiaPhone()
	{}
	void  showDecorate()
	{
		cout << name <<"的装饰"<< endl;
	}
};

class DecoratorPhone :public Phone
{
private :
	Phone* m_phone; //要装饰的手机
public:
	DecoratorPhone(Phone *phone)
		:m_phone(phone)
	{}
	virtual void showDecorate()
	{
		m_phone->showDecorate();
	}
};

class DecoratePhoneA : public DecoratorPhone //具体的装饰A
{
public :
	DecoratePhoneA(Phone* ph)
		:DecoratorPhone(ph)
	{}
	void showDecorate()
	{
		DecoratorPhone::showDecorate();
		AddDecorate();
	}
private:
	void AddDecorate()
	{
		cout <<"增加挂件" << endl;
	}
};
class DecoratePhoneB : public DecoratorPhone
{
public:
	DecoratePhoneB(Phone* ph)
		:DecoratorPhone(ph)
	{}
	void showDecorate()
	{
		DecoratorPhone::showDecorate();
		AddDecorate();
	}
private:
	void  AddDecorate()
	{
		cout << "屏幕贴膜"<< endl;
	}
};

int main(int argv, char *argc[]) {
   	Phone* ph = new NokiaPhone("16300");
	Phone *dpa = new DecoratePhoneA(ph);//增加挂件
	Phone* dpb = new DecoratePhoneB(dpa);//增加贴膜
    dpb->showDecorate();

	delete ph;
	delete dpa;
	delete dpb;
	return 0;
}
