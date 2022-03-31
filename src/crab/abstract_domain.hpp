#pragma once

#include <boost/optional/optional.hpp>
#include "cfg.hpp"
#include "linear_constraint.hpp"
#include "string_constraints.hpp"

#include "array_domain.hpp"
using check_require_func_t = std::function<bool(crab::domains::NumAbsDomain&, const crab::linear_constraint_t&, std::string)>;
using location_t = boost::optional<std::pair<label_t, uint32_t>>;
class abstract_domain_t {
  private:
    class abstract_domain_concept {
      public:
        abstract_domain_concept() = default;
        virtual ~abstract_domain_concept() = default;
        abstract_domain_concept(const abstract_domain_concept&) = delete;
        abstract_domain_concept(abstract_domain_concept&&) = delete;
        abstract_domain_concept& operator=(const abstract_domain_concept&) = delete;
        abstract_domain_concept& operator=(abstract_domain_concept&&) = delete;
        virtual std::unique_ptr<abstract_domain_concept> clone() const = 0;
        virtual void set_to_top() = 0;
        virtual void set_to_bottom() = 0;
        virtual bool is_bottom() const = 0;
        virtual bool is_top() const = 0;
        virtual bool operator<=(const abstract_domain_concept& abs) const = 0;
        virtual std::unique_ptr<abstract_domain_concept> operator|(const abstract_domain_concept& abs) const = 0;
        virtual std::unique_ptr<abstract_domain_concept> operator|(abstract_domain_concept&& abs) const = 0;
        virtual void operator|=(const abstract_domain_concept& abs) = 0;
        virtual void operator|=(abstract_domain_concept&& abs) = 0;
        virtual std::unique_ptr<abstract_domain_concept> operator&(const abstract_domain_concept& abs) const = 0;
        virtual std::unique_ptr<abstract_domain_concept> widen(const abstract_domain_concept& abs) const = 0;
        virtual std::unique_ptr<abstract_domain_concept> narrow(const abstract_domain_concept& abs) const = 0;
        virtual void operator()(const basic_block_t&, bool) = 0;
        virtual void operator()(const Undefined&, location_t loc = boost::none) = 0;
        virtual void operator()(const Bin&, location_t loc = boost::none) = 0;
        virtual void operator()(const Un&, location_t loc = boost::none) = 0;
        virtual void operator()(const LoadMapFd&, location_t loc = boost::none) = 0;
        virtual void operator()(const Call&, location_t loc = boost::none) = 0;
        virtual void operator()(const Exit&, location_t loc = boost::none) = 0;
        virtual void operator()(const Jmp&, location_t loc = boost::none) = 0;
        virtual void operator()(const Mem&, location_t loc = boost::none) = 0;
        virtual void operator()(const Packet&, location_t loc = boost::none) = 0;
        virtual void operator()(const LockAdd&, location_t loc = boost::none) = 0;
        virtual void operator()(const Assume&, location_t loc = boost::none) = 0;
        virtual void operator()(const Assert&, location_t loc = boost::none) = 0;
        virtual void write(std::ostream& os) const = 0;
        virtual std::string domain_name() const = 0;

        /* These operations are not very conventional for an abstract
           domain but it's convenient to have them */

        virtual crab::bound_t get_instruction_count_upper_bound() = 0;
        virtual string_invariant to_set() = 0;
        virtual void set_require_check(check_require_func_t f) = 0;
    }; // end class abstract_domain_concept

    template <typename Domain>
    class abstract_domain_model final : public abstract_domain_concept {
        Domain m_abs_val;

      public:
        explicit abstract_domain_model(Domain abs_val);
        std::unique_ptr<abstract_domain_concept> clone() const override;
        void set_to_top() override;
        void set_to_bottom() override;
        bool is_bottom() const override;
        bool is_top() const override;
        bool operator<=(const abstract_domain_concept& abs) const override;
        void operator|=(const abstract_domain_concept& abs) override;
        void operator|=(abstract_domain_concept&& abs) override;
        std::unique_ptr<abstract_domain_concept> operator|(const abstract_domain_concept& abs) const override;
        std::unique_ptr<abstract_domain_concept> operator|(abstract_domain_concept&& abs) const override;
        std::unique_ptr<abstract_domain_concept> operator&(const abstract_domain_concept& abs) const override;
        std::unique_ptr<abstract_domain_concept> widen(const abstract_domain_concept& abs) const override;
        std::unique_ptr<abstract_domain_concept> narrow(const abstract_domain_concept& abs) const override;
        void operator()(const basic_block_t& bb, bool check_termination) override;
        void operator()(const Undefined& s, location_t loc = boost::none) override;
        void operator()(const Bin& s, location_t loc = boost::none) override;
        void operator()(const Un& s, location_t loc = boost::none) override;
        void operator()(const LoadMapFd& s, location_t loc = boost::none) override;
        void operator()(const Call& s, location_t loc = boost::none) override;
        void operator()(const Exit& s, location_t loc = boost::none) override;
        void operator()(const Jmp& s, location_t loc = boost::none) override;
        void operator()(const Mem& s, location_t loc = boost::none) override;
        void operator()(const Packet& s, location_t loc = boost::none) override;
        void operator()(const LockAdd& s, location_t loc = boost::none) override;
        void operator()(const Assume& s, location_t loc = boost::none) override;
        void operator()(const Assert& s, location_t loc = boost::none) override;
        void write(std::ostream& os) const override;
        std::string domain_name() const override;
        crab::bound_t get_instruction_count_upper_bound() override;
        string_invariant to_set() override;
        void set_require_check(check_require_func_t f) override;
    }; // end class abstract_domain_model

    std::unique_ptr<abstract_domain_concept> m_concept;
    explicit abstract_domain_t(std::unique_ptr<abstract_domain_concept> concept_);

  public:
    template <typename Domain>
    abstract_domain_t(Domain abs_val);
    ~abstract_domain_t() = default;
    abstract_domain_t(const abstract_domain_t& o);
    abstract_domain_t& operator=(const abstract_domain_t& o);
    abstract_domain_t(abstract_domain_t&& o) = default;
    abstract_domain_t& operator=(abstract_domain_t&& o) = default;
    void set_to_top();
    void set_to_bottom();
    bool is_bottom() const;
    bool is_top() const;
    bool operator<=(const abstract_domain_t& abs) const;
    void operator|=(const abstract_domain_t& abs);
    void operator|=(abstract_domain_t&& abs);
    abstract_domain_t operator|(const abstract_domain_t& abs) const;
    abstract_domain_t operator|(abstract_domain_t&& abs) const;
    abstract_domain_t operator&(const abstract_domain_t& abs) const;
    abstract_domain_t widen(const abstract_domain_t& abs) const;
    abstract_domain_t narrow(const abstract_domain_t& abs) const;
    void operator()(const basic_block_t& bb, bool check_termination);
    void operator()(const Undefined& s, location_t loc = boost::none);
    void operator()(const Bin& s, location_t loc = boost::none);
    void operator()(const Un& s, location_t loc = boost::none);
    void operator()(const LoadMapFd& s, location_t loc = boost::none);
    void operator()(const Call& s, location_t loc = boost::none);
    void operator()(const Exit& s, location_t loc = boost::none);
    void operator()(const Jmp& s, location_t loc = boost::none);
    void operator()(const Mem& s, location_t loc = boost::none);
    void operator()(const Packet& s, location_t loc = boost::none);
    void operator()(const LockAdd& s, location_t loc = boost::none);
    void operator()(const Assume& s, location_t loc = boost::none);
    void operator()(const Assert& s, location_t loc = boost::none);
    void write(std::ostream& os) const;
    std::string domain_name() const;
    crab::bound_t get_instruction_count_upper_bound();
    string_invariant to_set();
    void set_require_check(check_require_func_t f);

    friend std::ostream& operator<<(std::ostream& o, const abstract_domain_t& dom);
};
